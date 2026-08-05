//! Diagnosing COPY path failures.
//!
//! The COPY formats do their file I/O in the *worker* process, so a COPY path is
//! resolved against the worker's filesystem and working directory — not the
//! filesystem of whoever ran the query. When DuckDB spawns the worker locally
//! those are the same thing and nothing here matters. When the worker runs in a
//! container (or on another host), they are not, and the bare OS error is
//! actively misleading: `COPY … TO 'out.cbor'` reports "No such file or
//! directory" for a directory that plainly exists on the user's machine.
//!
//! So every COPY path error is annotated with where the worker actually looked,
//! and a relative path issued to a containerized worker earns a warning even
//! when it succeeds — because it silently wrote inside the container.

use std::path::Path;
use std::sync::OnceLock;

use vgi_rpc::RpcError;

/// Where the worker is running, as far as the filesystem is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    /// Inside a container: paths resolve against an image filesystem that is
    /// unrelated to the caller's, apart from whatever is bind-mounted. The
    /// `&str` names the evidence, so the message can say why we think so.
    Container(&'static str),
    /// An ordinary process on this host.
    Host,
}

/// Detect containerization once per process (the answer cannot change).
///
/// Deliberately evidence-based rather than clever: each probe is a well-known
/// marker file, and the one that matched is reported in the diagnostic so a
/// wrong guess is visible rather than mysterious. Non-Linux hosts have none of
/// these and fall through to [`Runtime::Host`].
pub fn runtime() -> Runtime {
    static CACHED: OnceLock<Runtime> = OnceLock::new();
    *CACHED.get_or_init(|| {
        // Docker writes this marker into every container it builds.
        if Path::new("/.dockerenv").exists() {
            return Runtime::Container("/.dockerenv is present");
        }
        // Podman's equivalent.
        if Path::new("/run/.containerenv").exists() {
            return Runtime::Container("/run/.containerenv is present");
        }
        // Fall back to PID 1's cgroup membership, which names the runtime for
        // Docker/containerd/CRI-O and for Kubernetes pods.
        if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
            for marker in ["docker", "containerd", "kubepods", "crio", "libpod"] {
                if cgroup.contains(marker) {
                    return Runtime::Container(match marker {
                        "kubepods" => "PID 1 is in a Kubernetes pod cgroup",
                        _ => "PID 1 is in a container cgroup",
                    });
                }
            }
        }
        Runtime::Host
    })
}

/// The worker's working directory, for messages. Falls back to a placeholder
/// rather than failing — this only ever decorates an error.
fn cwd() -> String {
    std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string())
}

/// How the worker resolved `path`, spelled out. Relative paths are shown joined
/// to the working directory, since that is the part users cannot see.
fn resolved(path: &str) -> String {
    let p = Path::new(path);
    if p.is_absolute() {
        path.to_string()
    } else {
        format!("{}/{path}", cwd())
    }
}

/// The shared explanation of *why* a path the caller can see may not exist for
/// the worker. `None` on a host worker with an absolute path, where the plain OS
/// error is already the whole story.
fn worker_side_note(path: &str) -> Option<String> {
    let relative = !Path::new(path).is_absolute();
    match (runtime(), relative) {
        (Runtime::Container(evidence), _) => Some(format!(
            "This worker is running in a container ({evidence}), so the path resolved to \
             '{}' *inside the container* — not on the machine running the query. Write to a \
             path the container can see (a bind-mounted volume), or run the worker alongside \
             DuckDB.",
            resolved(path)
        )),
        (Runtime::Host, true) => Some(format!(
            "The path is relative, so the worker resolved it against its own working \
             directory: '{}'. That is the worker's cwd, which need not match the client's — \
             use an absolute path to remove the ambiguity.",
            resolved(path)
        )),
        (Runtime::Host, false) => None,
    }
}

/// Annotate a failed COPY file operation with where the worker actually looked.
///
/// `verb` is the attempted action ("create", "read"), used verbatim in the
/// message.
pub fn path_error(format: &str, verb: &str, path: &str, err: &std::io::Error) -> RpcError {
    let mut msg = format!("{format}: cannot {verb} '{path}': {err}.");
    msg.push_str(
        " COPY paths are resolved by the worker process, not by DuckDB — the file is opened \
         wherever the worker runs.",
    );
    if let Some(note) = worker_side_note(path) {
        msg.push(' ');
        msg.push_str(&note);
    } else {
        msg.push_str(&format!(
            " The worker's working directory is '{}'; the parent directory must exist and be \
             writable by the worker.",
            cwd()
        ));
    }
    RpcError::runtime_error(msg)
}

/// A warning for a COPY that will *succeed* but almost certainly not where the
/// caller intended: a relative path handed to a containerized worker writes
/// inside the container's ephemeral filesystem, which disappears with it.
/// `None` when there is nothing to warn about.
pub fn misleading_path_warning(format: &str, path: &str) -> Option<String> {
    let Runtime::Container(evidence) = runtime() else {
        return None;
    };
    if Path::new(path).is_absolute() {
        // An absolute path in a container is usually a deliberate bind mount.
        return None;
    }
    Some(format!(
        "{format}: '{path}' is a relative path and this worker runs in a container ({evidence}), \
         so it resolves to '{}' inside the container rather than on the machine running the \
         query — and is lost when the container exits. Use an absolute path under a mounted \
         volume.",
        resolved(path)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_paths_on_a_host_need_no_extra_explanation() {
        if runtime() != Runtime::Host {
            return; // running inside a container; the other arm applies
        }
        assert_eq!(worker_side_note("/tmp/out.cbor"), None);
    }

    #[test]
    fn relative_paths_always_explain_the_working_directory() {
        let note = worker_side_note("out.cbor").expect("a relative path always warrants a note");
        assert!(
            note.contains(&cwd()),
            "the note must name the directory the worker resolved against: {note}"
        );
    }

    #[test]
    fn path_errors_name_the_path_the_verb_and_the_worker() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "No such file or directory");
        let rendered = format!("{:?}", path_error("cbor", "create", "out.cbor", &err));
        assert!(rendered.contains("out.cbor"), "{rendered}");
        assert!(rendered.contains("create"), "{rendered}");
        // The load-bearing part: that the *worker* resolved the path.
        assert!(rendered.contains("worker"), "{rendered}");
    }

    #[test]
    fn a_host_worker_never_warns_about_a_relative_path() {
        if runtime() != Runtime::Host {
            return;
        }
        assert_eq!(misleading_path_warning("cbor", "out.cbor"), None);
        assert_eq!(misleading_path_warning("cbor", "/tmp/out.cbor"), None);
    }

    #[test]
    fn resolved_joins_relative_paths_but_leaves_absolute_ones() {
        assert_eq!(resolved("/tmp/x.cbor"), "/tmp/x.cbor");
        assert!(resolved("x.cbor").ends_with("/x.cbor"));
        assert!(resolved("x.cbor").starts_with(&cwd()));
    }
}
