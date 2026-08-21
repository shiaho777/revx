use super::*;

/// Process-wide free-list of SQLite connections keyed by absolute DB path.
static CONNECTION_POOL: OnceLock<std::sync::Mutex<BTreeMap<PathBuf, Vec<Connection>>>> =
    OnceLock::new();

pub(crate) fn canonicalize_db_path(db_path: &Path) -> PathBuf {
    if db_path.is_absolute() {
        db_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(db_path)
    }
}

pub(crate) fn connection_pool() -> &'static std::sync::Mutex<BTreeMap<PathBuf, Vec<Connection>>> {
    CONNECTION_POOL.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

pub(crate) fn open_connection_fresh(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    ensure_pragmas(&conn, db_path)?;
    ensure_schema(&conn, db_path)?;
    Ok(conn)
}

/// Dedicated connection for long-running transactions (analysis ingest).
pub(crate) fn open_connection(db_path: &Path) -> Result<Connection> {
    open_connection_fresh(db_path)
}

/// Pooled connection returned to the free-list on drop.
pub struct PooledConnection {
    key: PathBuf,
    conn: Option<Connection>,
}

impl PooledConnection {
    pub(crate) fn checkout(db_path: &Path) -> Result<Self> {
        let key = canonicalize_db_path(db_path);
        let mut pool = connection_pool().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(slot) = pool.get_mut(&key)
            && let Some(conn) = slot.pop()
        {
            return Ok(Self {
                key,
                conn: Some(conn),
            });
        }
        drop(pool);
        Ok(Self {
            key,
            conn: Some(open_connection_fresh(db_path)?),
        })
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let mut pool = connection_pool().lock().unwrap_or_else(|p| p.into_inner());
            let slot = pool.entry(self.key.clone()).or_default();
            if slot.len() < 2 {
                slot.push(conn);
            }
        }
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("pooled connection")
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("pooled connection")
    }
}
