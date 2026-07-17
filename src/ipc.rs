//! Platform-independent IPC transport used by the daemon.
//!
//! * **Unix** — Unix-domain socket at `~/.agent-password/daemon.sock`
//!   (mode 0600, created fresh on each daemon start).
//! * **Windows** — Named pipe `\\.\pipe\<dir-stem>` derived from the same
//!   app-state path, providing equivalent security (only the
//!   creating user can open a pipe by default).
//!
//! Both sides present a single `IpcStream` type that implements `Read`,
//! `Write`, and `try_clone`, so the rest of `daemon.rs` is identical on
//! every platform.

pub use imp::{bind, connect, IpcStream};

// ---------------------------------------------------------------------------
// Unix — UnixListener / UnixStream
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use std::fs;
    use std::io::{self, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    use anyhow::{Context, Result};

    pub struct IpcListener(UnixListener);

    pub struct IpcStream(UnixStream);

    impl IpcStream {
        pub fn try_clone(&self) -> Result<IpcStream> {
            self.0
                .try_clone()
                .map(IpcStream)
                .context("failed to clone IPC stream")
        }
    }

    impl Read for IpcStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for IpcStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl IpcListener {
        /// Accept the next incoming connection, blocking until one arrives.
        pub fn accept(&self) -> Result<IpcStream> {
            self.0
                .accept()
                .map(|(s, _)| IpcStream(s))
                .context("failed to accept IPC connection")
        }

        pub fn incoming(&self) -> Incoming<'_> {
            Incoming(self)
        }
    }

    pub struct Incoming<'a>(&'a IpcListener);

    impl Iterator for Incoming<'_> {
        type Item = Result<IpcStream>;
        fn next(&mut self) -> Option<Self::Item> {
            Some(self.0.accept())
        }
    }

    /// Create the listener, removing any stale socket first.
    pub fn bind() -> Result<IpcListener> {
        let socket_path = crate::paths::socket_path()?;
        if socket_path.exists() {
            let _ = fs::remove_file(&socket_path);
        }
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("failed to bind {}", socket_path.display()))?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", socket_path.display()))?;
        Ok(IpcListener(listener))
    }

    /// Connect to a running daemon.
    pub fn connect() -> Result<IpcStream> {
        let socket_path = crate::paths::socket_path()?;
        UnixStream::connect(&socket_path)
            .map(IpcStream)
            .with_context(|| format!("failed to connect to {}", socket_path.display()))
    }
}

// ---------------------------------------------------------------------------
// Windows — Named Pipes via Win32 API
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::windows::io::FromRawHandle;

    use anyhow::{anyhow, Context, Result};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE,
        OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    // PIPE_ACCESS_DUPLEX (3) — open-mode flag for CreateNamedPipeW.
    // Not re-exported from Win32::System::Pipes in windows 0.58; define inline.
    const PIPE_ACCESS_DUPLEX: FILE_FLAGS_AND_ATTRIBUTES = FILE_FLAGS_AND_ATTRIBUTES(3);
    // GENERIC_READ (0x80000000) | GENERIC_WRITE (0x40000000) for CreateFileW.
    // In windows 0.58 CreateFileW takes a plain u32 for dwDesiredAccess.
    const GENERIC_RW: u32 = 0xC000_0000u32;

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0u16)).collect()
    }

    // -----------------------------------------------------------------------
    // IpcStream wraps a File backed by a named-pipe handle.
    // File::try_clone() on Windows uses DuplicateHandle internally.
    // -----------------------------------------------------------------------

    pub struct IpcStream(File);

    impl IpcStream {
        pub fn try_clone(&self) -> Result<IpcStream> {
            self.0
                .try_clone()
                .map(IpcStream)
                .context("failed to clone IPC stream")
        }
    }

    impl Read for IpcStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for IpcStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    // -----------------------------------------------------------------------
    // IpcListener creates a new pipe instance for every inbound connection.
    // Named pipes differ from TCP/Unix sockets: each call to ConnectNamedPipe
    // consumes one pipe instance, so the listener creates a fresh instance
    // before each blocking wait.
    // -----------------------------------------------------------------------

    pub struct IpcListener {
        name: String,
    }

    impl IpcListener {
        pub fn accept(&self) -> Result<IpcStream> {
            accept_one(&self.name)
        }

        pub fn incoming(&self) -> Incoming<'_> {
            Incoming(self)
        }
    }

    pub struct Incoming<'a>(&'a IpcListener);

    impl Iterator for Incoming<'_> {
        type Item = Result<IpcStream>;
        fn next(&mut self) -> Option<Self::Item> {
            Some(self.0.accept())
        }
    }

    /// Create a pipe instance, wait for a client, and return the connected stream.
    fn accept_one(name: &str) -> Result<IpcStream> {
        let wide = to_wide(name);
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                None,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(anyhow!(
                "failed to create named pipe {}: {}",
                name,
                io::Error::last_os_error()
            ));
        }

        // ConnectNamedPipe blocks until a client connects.
        // ERROR_PIPE_CONNECTED means the client connected before we called
        // ConnectNamedPipe — that is still a success.
        match unsafe { ConnectNamedPipe(handle, None) } {
            Ok(()) => {}
            Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => {}
            Err(e) => {
                let _ = unsafe { CloseHandle(handle) };
                return Err(anyhow!("ConnectNamedPipe failed: {e}"));
            }
        }

        // SAFETY: the handle is valid and we are transferring ownership to File.
        Ok(IpcStream(unsafe {
            File::from_raw_handle(handle.0 as *mut std::ffi::c_void)
        }))
    }

    /// Create the listener.  On Windows there is no socket file to clean up.
    pub fn bind() -> Result<IpcListener> {
        let name = crate::paths::pipe_name()?;
        // Validate the name by creating (and immediately closing) a test instance.
        let wide = to_wide(&name);
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                None,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(anyhow!(
                "failed to create named pipe {}: {}",
                name,
                io::Error::last_os_error()
            ));
        }
        let _ = unsafe { CloseHandle(handle) };
        Ok(IpcListener { name })
    }

    /// Connect to a running daemon pipe.
    pub fn connect() -> Result<IpcStream> {
        let name = crate::paths::pipe_name()?;
        let wide = to_wide(&name);

        loop {
            match unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    GENERIC_RW,
                    FILE_SHARE_NONE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    HANDLE(std::ptr::null_mut()),
                )
            } {
                Ok(handle) => {
                    return Ok(IpcStream(unsafe {
                        File::from_raw_handle(handle.0 as *mut std::ffi::c_void)
                    }));
                }
                Err(e) if e.code() == windows::Win32::Foundation::ERROR_PIPE_BUSY.to_hresult() => {
                    // All instances busy; wait up to 5 s then retry.
                    let _ = unsafe { WaitNamedPipeW(PCWSTR(wide.as_ptr()), 5000) };
                }
                Err(e) => return Err(anyhow!("failed to connect to named pipe {name}: {e}")),
            }
        }
    }
}
