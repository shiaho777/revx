use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

const INTERN_CAP_PER_SHARD: usize = 16384;
const SHARD_COUNT: usize = 128;
const LOCAL_CAP: usize = 8192;
const HEX: &[u8; 16] = b"0123456789abcdef";

type InternMap = HashMap<Box<str>, Arc<str>>;

static STRING_INTERN: OnceLock<[RwLock<InternMap>; SHARD_COUNT]> = OnceLock::new();

thread_local! {
    static LOCAL_INTERN: RefCell<InternMap> = RefCell::new(HashMap::with_capacity(256));
}

fn tables() -> &'static [RwLock<InternMap>; SHARD_COUNT] {
    STRING_INTERN.get_or_init(|| std::array::from_fn(|_| RwLock::new(HashMap::with_capacity(256))))
}

#[inline]
fn shard_index(value: &str) -> usize {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash as usize) & (SHARD_COUNT - 1)
}

fn intern_in_shard(value: &str) -> Arc<str> {
    if value.is_empty() {
        return Arc::from("");
    }

    if let Some(existing) = LOCAL_INTERN.with(|local| local.borrow().get(value).cloned()) {
        return existing;
    }

    let shard = &tables()[shard_index(value)];
    if let Ok(guard) = shard.read() {
        if let Some(existing) = guard.get(value) {
            let owned = Arc::clone(existing);
            cache_local(value, Arc::clone(&owned));
            return owned;
        }
    }

    let mut guard = shard.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = guard.get(value) {
        let owned = Arc::clone(existing);
        drop(guard);
        cache_local(value, Arc::clone(&owned));
        return owned;
    }
    if guard.len() >= INTERN_CAP_PER_SHARD {
        let owned: Arc<str> = Arc::from(value);
        drop(guard);
        cache_local(value, Arc::clone(&owned));
        return owned;
    }
    let owned: Arc<str> = Arc::from(value);
    guard.insert(Box::from(value), Arc::clone(&owned));
    drop(guard);
    cache_local(value, Arc::clone(&owned));
    owned
}

#[inline]
fn cache_local(value: &str, owned: Arc<str>) {
    LOCAL_INTERN.with(|local| {
        let mut map = local.borrow_mut();
        if map.len() >= LOCAL_CAP {
            map.clear();
        }
        map.insert(Box::from(value), owned);
    });
}

pub fn intern_str(value: &str) -> Arc<str> {
    intern_in_shard(value)
}

pub fn intern_str_local(value: &str) -> Arc<str> {
    if value.is_empty() {
        return Arc::from("");
    }
    LOCAL_INTERN.with(|local| {
        let mut map = local.borrow_mut();
        if let Some(existing) = map.get(value) {
            return Arc::clone(existing);
        }
        if map.len() >= LOCAL_CAP {
            map.clear();
        }
        let owned: Arc<str> = Arc::from(value);
        map.insert(Box::from(value), Arc::clone(&owned));
        owned
    })
}

pub fn arm64_len_marker() -> Arc<str> {
    static MARKER: OnceLock<Arc<str>> = OnceLock::new();
    Arc::clone(MARKER.get_or_init(|| Arc::from("........")))
}

pub fn static_str(value: &'static str) -> Arc<str> {
    thread_local! {
        static CACHE: RefCell<HashMap<&'static str, Arc<str>>> =
            RefCell::new(HashMap::with_capacity(32));
    }
    CACHE.with(|slot| {
        let mut map = slot.borrow_mut();
        if let Some(existing) = map.get(value) {
            return Arc::clone(existing);
        }
        let owned: Arc<str> = Arc::from(value);
        map.insert(value, Arc::clone(&owned));
        owned
    })
}

pub fn intern_string(value: String) -> Arc<str> {
    if value.is_empty() {
        return Arc::from("");
    }

    if let Some(existing) = LOCAL_INTERN.with(|local| local.borrow().get(value.as_str()).cloned()) {
        return existing;
    }

    let shard = &tables()[shard_index(value.as_str())];
    if let Ok(guard) = shard.read() {
        if let Some(existing) = guard.get(value.as_str()) {
            let owned = Arc::clone(existing);
            cache_local(value.as_str(), Arc::clone(&owned));
            return owned;
        }
    }

    let mut guard = shard.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = guard.get(value.as_str()) {
        let owned = Arc::clone(existing);
        drop(guard);
        cache_local(value.as_str(), Arc::clone(&owned));
        return owned;
    }
    if guard.len() >= INTERN_CAP_PER_SHARD {
        let owned: Arc<str> = Arc::from(value.as_str());
        drop(guard);
        cache_local(value.as_str(), Arc::clone(&owned));
        return owned;
    }
    let owned: Arc<str> = Arc::from(value.as_str());
    guard.insert(Box::from(value), Arc::clone(&owned));
    drop(guard);
    cache_local(owned.as_ref(), Arc::clone(&owned));
    owned
}

pub fn intern_hex(bytes: &[u8]) -> Arc<str> {
    if bytes.is_empty() {
        return intern_str("");
    }
    if bytes.len() <= 16 {
        let mut buf = [0u8; 32];
        for (index, byte) in bytes.iter().enumerate() {
            buf[index * 2] = HEX[(byte >> 4) as usize];
            buf[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
        }
        let hex = std::str::from_utf8(&buf[..bytes.len() * 2]).unwrap_or("");
        if bytes.len() == 4 {
            return intern_hex_local(hex);
        }
        return intern_str(hex);
    }
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    intern_string(encoded)
}

fn intern_hex_local(value: &str) -> Arc<str> {
    if let Some(existing) = LOCAL_INTERN.with(|local| local.borrow().get(value).cloned()) {
        return existing;
    }
    let owned: Arc<str> = Arc::from(value);
    cache_local(value, Arc::clone(&owned));
    owned
}
