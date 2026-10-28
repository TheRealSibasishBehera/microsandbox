//! Resource limit helpers shared between PID 1 init (sandbox-wide baseline),
//! agentd's own open-file limit, and exec sessions (per-request limits).

use std::sync::{Once, OnceLock};

use microsandbox_protocol::exec::{ExecRlimit, RlimitResource};

use crate::error::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Open-file limit agentd sets for itself, soft and hard.
///
/// Every guest connection agentd relays holds one of its descriptors, and a sandbox may hold
/// several thousand at once. 65,536 leaves room for that many connections plus exec pipes, PTYs and
/// file handles, while still bounding what one agentd can pin. Descriptors cost nothing until used.
pub(crate) const AGENTD_OPEN_FILE_LIMIT: u64 = 65_536;

/// Kernel ceiling for any process's open-file limit.
const NR_OPEN_PATH: &str = "/proc/sys/fs/nr_open";

/// Open-file limit agentd had at startup, before raising its own, recorded once.
static STARTUP_OPEN_FILE_LIMIT: OnceLock<libc::rlimit> = OnceLock::new();

/// Reports, once, that exec children get a lower open-file limit than agentd started with.
static LOWERED_OPEN_FILE_NOTICE: Once = Once::new();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Limits an exec child applies between fork and exec, prepared before the fork.
pub(crate) struct ExecChildLimits {
    /// agentd's open-file limit as recorded at startup, so the child never keeps agentd's raised
    /// limit. `None` when the request sets its own. Restoring it is best effort: a failure leaves
    /// the child with agentd's limit and never fails the exec.
    pub(crate) startup_open_files: Option<libc::rlimit>,

    /// Requested limits, applied in order after the startup limit; any failure fails the exec.
    pub(crate) requested: Vec<(libc::c_int, libc::rlimit)>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Raises agentd's own open-file limit, soft and hard, to 65,536 capped by `fs.nr_open`, never
/// below the inherited hard limit.
///
/// Exec children get back the limit agentd had when this ran, so guest processes keep the limit
/// they had before; a later change to agentd's own limit (for example with `prlimit`) does not
/// reach them. Call it once, after any PID 1 handoff, so a separate init never inherits the raised
/// limit.
pub fn raise_own_open_file_limit() -> AgentdResult<()> {
    let mut startup = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut startup) } != 0 {
        return Err(AgentdError::Init(format!(
            "failed to read open-file limit: {}",
            std::io::Error::last_os_error()
        )));
    }
    let nr_open = read_nr_open()?;
    STARTUP_OPEN_FILE_LIMIT.get_or_init(|| startup);

    let target = AGENTD_OPEN_FILE_LIMIT.min(nr_open).max(startup.rlim_max);
    let raised = libc::rlimit {
        rlim_cur: target,
        rlim_max: target,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
        return Err(AgentdError::Init(format!(
            "failed to raise open-file limit to {target}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Maps a wire-format resource name to the Linux `RLIMIT_*` constant, or
/// `None` if the name is not a known [`RlimitResource`].
pub(crate) fn parse_rlimit_resource(name: &str) -> Option<libc::c_int> {
    RlimitResource::try_from(name).ok().map(resource_to_libc_id)
}

/// Pre-parses rlimits into `(resource_id, rlimit)` tuples ready for
/// `setrlimit()`. Unknown resource names are filtered out.
pub(crate) fn to_libc(rlimits: &[ExecRlimit]) -> Vec<(libc::c_int, libc::rlimit)> {
    rlimits
        .iter()
        .filter_map(|rl| {
            Some((
                parse_rlimit_resource(&rl.resource)?,
                libc::rlimit {
                    rlim_cur: rl.soft,
                    rlim_max: rl.hard,
                },
            ))
        })
        .collect()
}

/// Prepares an exec child's limits: agentd's startup open-file limit, then the requested ones.
pub(crate) fn exec_child_limits(rlimits: &[ExecRlimit]) -> ExecChildLimits {
    let startup = STARTUP_OPEN_FILE_LIMIT.get().copied();
    let nr_open = startup.and_then(|_| read_nr_open().ok());
    let limits = child_limits(startup, nr_open, to_libc(rlimits));

    if let (Some(startup), Some(restored)) = (startup, limits.startup_open_files)
        && restored.rlim_max < startup.rlim_max
    {
        LOWERED_OPEN_FILE_NOTICE.call_once(|| {
            eprintln!(
                "agentd: {NR_OPEN_PATH} is below the startup open-file limit {}; \
                 exec children get {}:{}",
                startup.rlim_max, restored.rlim_cur, restored.rlim_max
            );
        });
    }
    limits
}

/// Pairs the requested limits with the startup open-file limit, unless the request sets its own.
///
/// The kernel refuses any open-file limit above `fs.nr_open`, even a lowering one, so a startup
/// hard limit above the current `nr_open` is lowered to it, with the soft limit capped to match.
fn child_limits(
    startup: Option<libc::rlimit>,
    nr_open: Option<u64>,
    requested: Vec<(libc::c_int, libc::rlimit)>,
) -> ExecChildLimits {
    let open_files = resource_to_libc_id(RlimitResource::Nofile);
    let requests_open_files = requested
        .iter()
        .any(|(resource, _)| *resource == open_files);
    let startup_open_files = startup
        .filter(|_| !requests_open_files)
        .map(|limit| match nr_open {
            Some(nr_open) if limit.rlim_max > nr_open => libc::rlimit {
                rlim_cur: limit.rlim_cur.min(nr_open),
                rlim_max: nr_open,
            },
            _ => limit,
        });
    ExecChildLimits {
        startup_open_files,
        requested,
    }
}

/// Reads the kernel's ceiling for open-file limits.
fn read_nr_open() -> AgentdResult<u64> {
    let value = std::fs::read_to_string(NR_OPEN_PATH)
        .map_err(|error| AgentdError::Init(format!("failed to read {NR_OPEN_PATH}: {error}")))?;
    value.trim().parse::<u64>().map_err(|error| {
        AgentdError::Init(format!("invalid {NR_OPEN_PATH} value {value:?}: {error}"))
    })
}

/// Applies sandbox-wide resource limits to the current process (PID 1).
///
/// Applied before other init work so every later guest process inherits the
/// raised baseline automatically, including bootstrap daemons that are not
/// started through the per-exec API.
///
/// Callers must have validated resource names upfront (e.g. via
/// [`BootParams::from_bootstrap`](crate::config::BootParams::from_bootstrap)); unknown
/// names here produce an [`AgentdError::Init`] rather than silently skipping.
pub(crate) fn apply_baseline(rlimits: &[ExecRlimit]) -> AgentdResult<()> {
    for rlimit in rlimits {
        let resource = parse_rlimit_resource(&rlimit.resource).ok_or_else(|| {
            AgentdError::Init(format!("unknown rlimit resource: {}", rlimit.resource))
        })?;
        let limit = libc::rlimit {
            rlim_cur: rlimit.soft,
            rlim_max: rlimit.hard,
        };
        if unsafe { libc::setrlimit(resource as _, &limit) } != 0 {
            return Err(AgentdError::Init(format!(
                "failed to apply rlimit {}={}:{}: {}",
                rlimit.resource,
                rlimit.soft,
                rlimit.hard,
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

/// Maps a [`RlimitResource`] to its Linux `RLIMIT_*` integer id.
fn resource_to_libc_id(resource: RlimitResource) -> libc::c_int {
    // Linux x86_64 RLIMIT_* values for resources not exposed by libc on all platforms.
    const RLIMIT_LOCKS: libc::c_int = 10;
    const RLIMIT_SIGPENDING: libc::c_int = 11;
    const RLIMIT_MSGQUEUE: libc::c_int = 12;
    const RLIMIT_NICE: libc::c_int = 13;
    const RLIMIT_RTPRIO: libc::c_int = 14;
    const RLIMIT_RTTIME: libc::c_int = 15;

    match resource {
        RlimitResource::Cpu => libc::RLIMIT_CPU as _,
        RlimitResource::Fsize => libc::RLIMIT_FSIZE as _,
        RlimitResource::Data => libc::RLIMIT_DATA as _,
        RlimitResource::Stack => libc::RLIMIT_STACK as _,
        RlimitResource::Core => libc::RLIMIT_CORE as _,
        RlimitResource::Rss => libc::RLIMIT_RSS as _,
        RlimitResource::Nproc => libc::RLIMIT_NPROC as _,
        RlimitResource::Nofile => libc::RLIMIT_NOFILE as _,
        RlimitResource::Memlock => libc::RLIMIT_MEMLOCK as _,
        RlimitResource::As => libc::RLIMIT_AS as _,
        RlimitResource::Locks => RLIMIT_LOCKS,
        RlimitResource::Sigpending => RLIMIT_SIGPENDING,
        RlimitResource::Msgqueue => RLIMIT_MSGQUEUE,
        RlimitResource::Nice => RLIMIT_NICE,
        RlimitResource::Rtprio => RLIMIT_RTPRIO,
        RlimitResource::Rttime => RLIMIT_RTTIME,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(soft: u64, hard: u64) -> libc::rlimit {
        libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        }
    }

    fn request(resource: &str, soft: u64, hard: u64) -> ExecRlimit {
        ExecRlimit {
            resource: resource.into(),
            soft,
            hard,
        }
    }

    fn pairs(limits: Vec<(libc::c_int, libc::rlimit)>) -> Vec<(libc::c_int, u64, u64)> {
        limits
            .into_iter()
            .map(|(resource, limit)| (resource, limit.rlim_cur, limit.rlim_max))
            .collect()
    }

    #[test]
    fn exec_child_limits_restore_the_startup_open_file_limit() {
        let limits = child_limits(
            Some(limit(1024, 4096)),
            Some(1_048_576),
            to_libc(&[request("memlock", 64, 128)]),
        );

        assert_eq!(
            limits
                .startup_open_files
                .map(|limit| (limit.rlim_cur, limit.rlim_max)),
            Some((1024, 4096))
        );
        assert_eq!(
            pairs(limits.requested),
            vec![(resource_to_libc_id(RlimitResource::Memlock), 64, 128)]
        );
    }

    #[test]
    fn exec_child_limits_leave_open_files_to_a_request_that_sets_them() {
        let limits = child_limits(
            Some(limit(1024, 4096)),
            Some(1_048_576),
            to_libc(&[request("NOFILE", 2048, 8192), request("memlock", 64, 128)]),
        );

        assert!(limits.startup_open_files.is_none());
        assert_eq!(
            pairs(limits.requested),
            vec![
                (resource_to_libc_id(RlimitResource::Nofile), 2048, 8192),
                (resource_to_libc_id(RlimitResource::Memlock), 64, 128),
            ]
        );
    }

    #[test]
    fn exec_child_limits_fit_the_startup_open_files_under_a_lowered_nr_open() {
        let restored = |nr_open| {
            child_limits(Some(limit(1024, 4096)), nr_open, Vec::new())
                .startup_open_files
                .map(|limit| (limit.rlim_cur, limit.rlim_max))
        };

        assert_eq!(restored(Some(2048)), Some((1024, 2048)));
        assert_eq!(restored(Some(512)), Some((512, 512)));
        assert_eq!(restored(Some(4096)), Some((1024, 4096)));
        assert_eq!(restored(None), Some((1024, 4096)));
    }
}
