//! Resource limit helpers shared between PID 1 init (sandbox-wide baseline),
//! agentd's own open-file limit, and exec sessions (per-request limits).

use std::sync::OnceLock;

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

/// Open-file limit agentd inherited before raising its own, recorded once.
static INHERITED_OPEN_FILE_LIMIT: OnceLock<libc::rlimit> = OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Raises agentd's own open-file limit, soft and hard, to [`AGENTD_OPEN_FILE_LIMIT`] capped by
/// `fs.nr_open`, never below the inherited hard limit.
///
/// Exec children get the inherited limit back (see [`to_libc`]), so guest processes keep the
/// limit they had before. Call it once, after any PID 1 handoff, so a separate init never inherits
/// the raised limit.
pub fn raise_own_open_file_limit() -> AgentdResult<()> {
    let mut inherited = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut inherited) } != 0 {
        return Err(AgentdError::Init(format!(
            "failed to read open-file limit: {}",
            std::io::Error::last_os_error()
        )));
    }
    let nr_open = std::fs::read_to_string(NR_OPEN_PATH)
        .map_err(|error| AgentdError::Init(format!("failed to read {NR_OPEN_PATH}: {error}")))?;
    let nr_open = nr_open.trim().parse::<u64>().map_err(|error| {
        AgentdError::Init(format!("invalid {NR_OPEN_PATH} value {nr_open:?}: {error}"))
    })?;
    INHERITED_OPEN_FILE_LIMIT.get_or_init(|| inherited);

    let target = AGENTD_OPEN_FILE_LIMIT.min(nr_open).max(inherited.rlim_max);
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

/// Pre-parses an exec child's limits into `(resource_id, rlimit)` tuples ready for
/// `setrlimit()`, applied in order. Unknown resource names are filtered out.
pub(crate) fn to_libc(rlimits: &[ExecRlimit]) -> Vec<(libc::c_int, libc::rlimit)> {
    exec_child_limits(INHERITED_OPEN_FILE_LIMIT.get().copied(), rlimits)
}

/// Requested limits, preceded by the open-file limit agentd inherited unless the request sets its
/// own, so a child never keeps agentd's raised limit.
fn exec_child_limits(
    inherited_open_files: Option<libc::rlimit>,
    rlimits: &[ExecRlimit],
) -> Vec<(libc::c_int, libc::rlimit)> {
    let requests_open_files = rlimits.iter().any(|rl| {
        matches!(
            RlimitResource::try_from(rl.resource.as_str()),
            Ok(RlimitResource::Nofile)
        )
    });
    let inherited = inherited_open_files
        .filter(|_| !requests_open_files)
        .map(|limit| (resource_to_libc_id(RlimitResource::Nofile), limit));
    let requested = rlimits.iter().filter_map(|rl| {
        Some((
            parse_rlimit_resource(&rl.resource)?,
            libc::rlimit {
                rlim_cur: rl.soft,
                rlim_max: rl.hard,
            },
        ))
    });
    inherited.into_iter().chain(requested).collect()
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
    fn exec_child_limits_restore_inherited_open_files_before_requested_limits() {
        let limits = exec_child_limits(Some(limit(1024, 4096)), &[request("memlock", 64, 128)]);

        assert_eq!(
            pairs(limits),
            vec![
                (resource_to_libc_id(RlimitResource::Nofile), 1024, 4096),
                (resource_to_libc_id(RlimitResource::Memlock), 64, 128),
            ]
        );
    }

    #[test]
    fn exec_child_limits_leave_open_files_to_a_request_that_sets_them() {
        let limits = exec_child_limits(
            Some(limit(1024, 4096)),
            &[request("NOFILE", 2048, 8192), request("memlock", 64, 128)],
        );

        assert_eq!(
            pairs(limits),
            vec![
                (resource_to_libc_id(RlimitResource::Nofile), 2048, 8192),
                (resource_to_libc_id(RlimitResource::Memlock), 64, 128),
            ]
        );
    }
}
