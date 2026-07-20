use std::sync::OnceLock;
use std::time::{Duration, Instant};

const DEFAULT_JOBS: usize = 1;
const ABSOLUTE_MAX_JOBS: usize = 2;
const DEFAULT_WALL_SEC: u64 = 180;
const DEFAULT_RSS_KB: u64 = 8 * 1024;
const DEFAULT_CPU_SEC: u64 = 180;
const DEFAULT_NICE: i32 = 5;
const ABSOLUTE_MAX_RSS_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct ProcessResourceLimits {
    pub jobs: usize,
    pub wall_sec: u64,
    pub rss_kb: u64,
    pub cpu_sec: u64,
    pub nice: i32,
}

impl ProcessResourceLimits {
    pub fn from_env() -> Self {
        let job_cap = if std::env::var_os("REVX_FULL_MEM").is_some() {
            4
        } else {
            ABSOLUTE_MAX_JOBS
        };
        let jobs = std::env::var("REVX_JOBS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or(DEFAULT_JOBS)
            .min(job_cap);
        let available = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1);
        let jobs = jobs.min(available);
        let wall_sec = std::env::var("REVX_WALL_SEC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or(DEFAULT_WALL_SEC);
        let rss_kb = std::env::var("REVX_RSS_KB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .or_else(|| {
                std::env::var("REVX_RSS_MB")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|mb| mb.saturating_mul(1024))
            })
            .filter(|v| *v >= 64)
            .unwrap_or(DEFAULT_RSS_KB);
        let cpu_sec = std::env::var("REVX_CPU_SEC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or(DEFAULT_CPU_SEC);
        let nice = std::env::var("REVX_NICE")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(DEFAULT_NICE)
            .clamp(0, 19);
        Self {
            jobs,
            wall_sec,
            rss_kb,
            cpu_sec,
            nice,
        }
    }

    pub fn wall_limit(&self) -> Duration {
        Duration::from_secs(self.wall_sec)
    }

    pub fn rss_limit_bytes(&self) -> u64 {
        self.rss_kb.saturating_mul(1024).min(ABSOLUTE_MAX_RSS_BYTES)
    }
}

static APPLIED: OnceLock<ProcessResourceLimits> = OnceLock::new();

pub fn process_resource_limits() -> ProcessResourceLimits {
    *APPLIED.get_or_init(|| {
        let limits = ProcessResourceLimits::from_env();
        apply_os_limits(&limits);
        limits
    })
}

pub fn ensure_process_resource_limits() -> ProcessResourceLimits {
    process_resource_limits()
}

pub fn micro_mode() -> bool {
    revx_core::micro_mode()
}

pub fn lean_mode() -> bool {
    revx_core::lean_mode()
}

fn apply_os_limits(limits: &ProcessResourceLimits) {
    #[cfg(unix)]
    {
        lower_priority(limits.nice);
        set_qos_utility();
        set_rlimit_cpu(limits.cpu_sec);
    }
    let _ = limits;
}

#[cfg(unix)]
fn lower_priority(nice: i32) {
    unsafe {
        unsafe extern "C" {
            fn setpriority(which: i32, who: u32, prio: i32) -> i32;
        }
        const PRIO_PROCESS: i32 = 0;
        let _ = setpriority(PRIO_PROCESS, 0, nice);
    }
}

#[cfg(target_os = "macos")]
fn set_qos_utility() {
    unsafe {
        unsafe extern "C" {
            fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
        }
        const QOS_CLASS_UTILITY: u32 = 0x11;
        let _ = pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0);
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn set_qos_utility() {}

#[cfg(unix)]
fn set_rlimit_cpu(seconds: u64) {
    unsafe {
        unsafe extern "C" {
            fn setrlimit(resource: i32, rlim: *const Rlimit) -> i32;
        }
        #[repr(C)]
        struct Rlimit {
            rlim_cur: u64,
            rlim_max: u64,
        }
        const RLIMIT_CPU: i32 = 0;
        let soft = seconds.max(1);
        let hard = soft.saturating_add(5);
        let lim = Rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        let _ = setrlimit(RLIMIT_CPU, &lim);
    }
}

pub fn current_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        return macos_resident_size();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        unsafe {
            unsafe extern "C" {
                fn getrusage(who: i32, usage: *mut Rusage) -> i32;
            }
            #[repr(C)]
            struct Timeval {
                tv_sec: i64,
                tv_usec: i64,
            }
            #[repr(C)]
            struct Rusage {
                ru_utime: Timeval,
                ru_stime: Timeval,
                ru_maxrss: i64,
                _rest: [i64; 14],
            }
            const RUSAGE_SELF: i32 = 0;
            let mut usage = std::mem::MaybeUninit::<Rusage>::uninit();
            if getrusage(RUSAGE_SELF, usage.as_mut_ptr()) != 0 {
                return None;
            }
            let usage = usage.assume_init();
            if usage.ru_maxrss <= 0 {
                return None;
            }
            return Some((usage.ru_maxrss as u64).saturating_mul(1024));
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn macos_resident_size() -> Option<u64> {
    unsafe {
        unsafe extern "C" {
            fn mach_task_self() -> u32;
            fn task_info(
                target_task: u32,
                flavor: i32,
                task_info_out: *mut i32,
                task_info_outCnt: *mut u32,
            ) -> i32;
        }
        const MACH_TASK_BASIC_INFO: i32 = 20;
        const MACH_TASK_BASIC_INFO_COUNT: u32 = 12;
        #[repr(C)]
        struct MachTaskBasicInfo {
            virtual_size: u64,
            resident_size: u64,
            resident_size_max: u64,
            user_time: [i32; 2],
            system_time: [i32; 2],
            policy: i32,
            suspend_count: i32,
        }
        let mut info = std::mem::MaybeUninit::<MachTaskBasicInfo>::uninit();
        let mut count = MACH_TASK_BASIC_INFO_COUNT;
        let kr = task_info(
            mach_task_self(),
            MACH_TASK_BASIC_INFO,
            info.as_mut_ptr() as *mut i32,
            &mut count,
        );
        if kr != 0 {
            return None;
        }
        let info = info.assume_init();
        if info.resident_size == 0 {
            None
        } else {
            Some(info.resident_size)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetExceedKind {
    WallClock,
    Memory,
}

#[derive(Debug, Clone)]
pub struct AnalysisBudget {
    started: Instant,
    wall_limit: Duration,
    baseline_rss: u64,
    growth_limit_bytes: u64,
    exceeded: Option<BudgetExceedKind>,
}

impl AnalysisBudget {
    pub fn from_process_limits() -> Self {
        let limits = ensure_process_resource_limits();
        let baseline = current_rss_bytes().unwrap_or(0);
        let growth = limits.rss_limit_bytes().min(ABSOLUTE_MAX_RSS_BYTES);
        Self {
            started: Instant::now(),
            wall_limit: limits.wall_limit(),
            baseline_rss: baseline,
            growth_limit_bytes: growth,
            exceeded: None,
        }
    }

    pub fn check(&mut self) -> Result<(), BudgetExceedKind> {
        if let Some(kind) = self.exceeded {
            return Err(kind);
        }
        if self.started.elapsed() >= self.wall_limit {
            self.exceeded = Some(BudgetExceedKind::WallClock);
            return Err(BudgetExceedKind::WallClock);
        }
        if let Some(rss) = current_rss_bytes() {
            const NOISE: u64 = 64 * 1024;
            let growth = rss.saturating_sub(self.baseline_rss);
            if growth > self.growth_limit_bytes.saturating_add(NOISE) {
                self.exceeded = Some(BudgetExceedKind::Memory);
                return Err(BudgetExceedKind::Memory);
            }
        }
        Ok(())
    }

    pub fn exceeded(&self) -> Option<BudgetExceedKind> {
        self.exceeded
    }

    pub fn elapsed_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    pub fn deadline(&self) -> Instant {
        self.started + self.wall_limit
    }

    pub fn remaining(&self) -> Duration {
        self.wall_limit.saturating_sub(self.started.elapsed())
    }

    pub fn rss_limit_bytes(&self) -> u64 {
        self.baseline_rss.saturating_add(self.growth_limit_bytes)
    }

    pub fn growth_limit_bytes(&self) -> u64 {
        self.growth_limit_bytes
    }

    pub fn baseline_rss(&self) -> u64 {
        self.baseline_rss
    }

    pub fn rebaseline(&mut self) {
        if let Some(rss) = current_rss_bytes() {
            self.baseline_rss = rss;
        }
        self.exceeded = None;
    }
}

pub fn analysis_worker_count() -> usize {
    ensure_process_resource_limits().jobs
}
