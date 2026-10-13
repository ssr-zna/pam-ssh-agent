use anyhow::{Context, Result, anyhow};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub const AGENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Connects to the agent socket with the filesystem permissions of the real user of the
/// process, so that a setuid caller such as sudo can only reach sockets its invoking user
/// could reach itself. PAM_USER is not used: sudo sets it to the target user under
/// rootpw, targetpw and runaspw.
pub fn connect_as_caller(path: &Path, timeout: Duration) -> Result<DeadlineStream> {
    let stream = {
        let _ids = FsIds::switch_to_real()?;
        UnixStream::connect(path)
    }
    .with_context(|| format!("Failed to connect to ssh-agent at {path:?}"))?;
    Ok(DeadlineStream::new(stream, timeout))
}

pub struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}

impl DeadlineStream {
    pub fn new(stream: UnixStream, timeout: Duration) -> Self {
        DeadlineStream {
            stream,
            deadline: Instant::now() + timeout,
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        match self.deadline.checked_duration_since(Instant::now()) {
            Some(remaining) if !remaining.is_zero() => Ok(remaining),
            _ => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "ssh-agent did not respond in time",
            )),
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(target_os = "linux")]
struct FsIds {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

#[cfg(target_os = "linux")]
impl FsIds {
    fn switch_to_real() -> Result<Self> {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let previous = FsIds {
            gid: unsafe { libc::setfsgid(gid) } as libc::gid_t,
            uid: unsafe { libc::setfsuid(uid) } as libc::uid_t,
        };
        let current_gid = unsafe { libc::setfsgid(gid) } as libc::gid_t;
        let current_uid = unsafe { libc::setfsuid(uid) } as libc::uid_t;
        if current_uid != uid || current_gid != gid {
            return Err(anyhow!("Failed to switch filesystem ids to {uid}:{gid}"));
        }
        Ok(previous)
    }
}

#[cfg(target_os = "linux")]
impl Drop for FsIds {
    fn drop(&mut self) {
        unsafe {
            libc::setfsuid(self.uid);
            libc::setfsgid(self.gid);
        }
    }
}

#[cfg(not(target_os = "linux"))]
struct FsIds;

#[cfg(not(target_os = "linux"))]
impl FsIds {
    fn switch_to_real() -> Result<Self> {
        Err(anyhow!(
            "Connecting with the caller's permissions is only supported on Linux"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::DeadlineStream;
    use ssh_agent_client_rs::Client;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::{Duration, Instant};

    #[test]
    fn test_unresponsive_agent_times_out() -> anyhow::Result<()> {
        let dir = std::env::temp_dir().join(format!("pam-ssh-agent-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("agent.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;

        let stream = UnixStream::connect(&path)?;
        let _accepted = listener.accept()?;
        let mut client = Client::with_read_write(Box::new(DeadlineStream::new(
            stream,
            Duration::from_millis(200),
        )));

        let start = Instant::now();
        assert!(client.list_all_identities().is_err());
        assert!(start.elapsed() < Duration::from_secs(2));

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
