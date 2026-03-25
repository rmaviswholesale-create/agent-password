use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::biometric;
use crate::ipc::{self, IpcStream};
use crate::keychain;
use crate::paths;
use crate::protocol::{
    PendingRequest, Request, RequestedSecret, Response, SessionState, SessionStatus,
};
use crate::storage::{self, SecretInput};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Ensure the background daemon is running, starting it if necessary.
pub fn ensure_daemon_running() -> Result<()> {
    if try_connect().is_ok() {
        return Ok(());
    }

    // On Unix, remove any stale socket file before spawning the daemon.
    #[cfg(unix)]
    {
        let socket_path = paths::socket_path()?;
        if socket_path.exists() {
            let _ = fs::remove_file(&socket_path);
        }
    }

    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let mut command = Command::new(current_exe);
    command
        .arg("__daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Detach the daemon from the calling process so it survives after the CLI exits.
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    // On Windows use creation flags instead of setsid:
    //   DETACHED_PROCESS   (0x00000008) — detach from parent console
    //   CREATE_NO_WINDOW   (0x08000000) — suppress implicit console window
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0000_0008 | 0x0800_0000);
    }

    command.spawn().context("failed to start internal daemon")?;

    for _ in 0..50 {
        if try_connect().is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(anyhow!("internal daemon did not become ready"))
}

/// Send a request to the daemon and return its response.
pub fn send(request: &Request) -> Result<Response> {
    ensure_daemon_running()?;
    let mut stream = try_connect().context("failed to connect to internal daemon")?;

    {
        let mut writer = BufWriter::new(&mut stream);
        serde_json::to_writer(&mut writer, request)
            .context("failed to serialize daemon request")?;
        writer
            .write_all(b"\n")
            .context("failed to write daemon request terminator")?;
        writer.flush().context("failed to flush daemon request")?;
    }

    let mut response_line = String::new();
    let mut reader = BufReader::new(&mut stream);
    reader
        .read_line(&mut response_line)
        .context("failed to read daemon response")?;
    if response_line.trim().is_empty() {
        return Err(anyhow!("internal daemon returned an empty response"));
    }
    let response: Response =
        serde_json::from_str(&response_line).context("failed to decode daemon response")?;
    Ok(response)
}

/// Main loop executed inside the daemon subprocess.
pub fn run_daemon() -> Result<()> {
    let app_dir = paths::app_dir()?;
    fs::create_dir_all(&app_dir)
        .with_context(|| format!("failed to create {}", app_dir.display()))?;

    let listener = ipc::bind()?;
    let shared = Arc::new(Mutex::new(Daemon::new()?));

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("failed to accept daemon connection: {error:#}");
                continue;
            }
        };

        let shared = Arc::clone(&shared);
        thread::spawn(move || {
            if let Err(error) = handle_connection(stream, shared) {
                eprintln!("failed to handle daemon request: {error:#}");
            }
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn try_connect() -> Result<IpcStream> {
    ipc::connect()
}

fn handle_connection(stream: IpcStream, shared: Arc<Mutex<Daemon>>) -> Result<()> {
    // Clone gives us two independent handles to the same pipe/socket so we
    // can wrap one in BufReader and the other in BufWriter.
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .context("failed to clone daemon stream")?,
    );
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("failed to read daemon request")?;
    let request: Request =
        serde_json::from_str(&request_line).context("failed to decode daemon request payload")?;

    let response = {
        let mut daemon = shared.lock().unwrap();
        match daemon.handle(request) {
            Ok(response) => response,
            Err(error) => Response::Error {
                message: format!("{error:#}"),
            },
        }
    };

    let mut writer = BufWriter::new(stream);
    serde_json::to_writer(&mut writer, &response).context("failed to encode daemon response")?;
    writer
        .write_all(b"\n")
        .context("failed to write daemon response terminator")?;
    writer.flush().context("failed to flush daemon response")
}

// ---------------------------------------------------------------------------
// Daemon state machine
// ---------------------------------------------------------------------------

struct Daemon {
    database_path: PathBuf,
    session: Option<SessionState>,
}

impl Daemon {
    fn new() -> Result<Self> {
        Ok(Self {
            database_path: paths::database_path()?,
            session: None,
        })
    }

    fn handle(&mut self, request: Request) -> Result<Response> {
        match request {
            Request::VaultInit => {
                if self.database_path.exists() {
                    return Err(anyhow!(
                        "vault already exists at {}",
                        self.database_path.display()
                    ));
                }
                storage::initialize(&self.database_path)?;
                let key = crate::crypto::generate_vault_key()?;
                keychain::store_vault_key(&key)?;
                Ok(Response::Ack {
                    message: "vault initialized".into(),
                })
            }
            Request::SessionCreate { replace } => {
                if self.session.is_some() && !replace {
                    return Err(anyhow!(
                        "a shared session already exists; use `agent-password session create --replace`"
                    ));
                }
                self.session = Some(SessionState {
                    next_request_id: 1,
                    ..SessionState::default()
                });
                Ok(Response::Ack {
                    message: "shared session created".into(),
                })
            }
            Request::SessionStatus => Ok(Response::SessionStatus {
                status: self.status(),
            }),
            Request::SessionClose => {
                self.session = None;
                Ok(Response::Ack {
                    message: "shared session closed".into(),
                })
            }
            Request::SessionClear => {
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| anyhow!("no shared session exists"))?;
                session.approved_ids.clear();
                Ok(Response::Ack {
                    message: "session grants cleared".into(),
                })
            }
            Request::SecretPut {
                id,
                kind,
                title,
                service,
                username,
                tags,
                fields,
            } => {
                storage::initialize(&self.database_path)?;
                let key = self.load_key_for_management()?;
                let metadata = storage::upsert_secret(
                    &self.database_path,
                    SecretInput {
                        id,
                        kind,
                        title,
                        service,
                        username,
                        tags,
                        fields,
                    },
                    &key,
                )?;
                Ok(Response::Ack {
                    message: format!("stored secret `{}`", metadata.id),
                })
            }
            Request::SecretDelete { id } => {
                storage::delete_secret(&self.database_path, &id)?;
                if let Some(session) = &mut self.session {
                    session.approved_ids.remove(&id);
                    for request in session.pending_requests.values_mut() {
                        request.secret_ids.retain(|candidate| candidate != &id);
                    }
                }
                Ok(Response::Ack {
                    message: format!("deleted secret `{id}`"),
                })
            }
            Request::SecretsList => {
                self.session
                    .as_ref()
                    .ok_or_else(|| anyhow!("no shared session exists"))?;
                Ok(Response::SecretsList {
                    secrets: storage::list_secrets(&self.database_path)?,
                })
            }
            Request::SecretShow { id } => {
                let secret = storage::get_secret_metadata(&self.database_path, &id)?
                    .ok_or_else(|| anyhow!("secret `{id}` does not exist"))?;
                Ok(Response::SecretShow { secret })
            }
            Request::SecretsRequest {
                ids,
                requester,
                reason,
            } => {
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| anyhow!("no shared session exists"))?;
                if ids.is_empty() {
                    return Err(anyhow!("request must contain at least one secret id"));
                }
                let mut deduped = BTreeSet::new();
                for id in ids {
                    if !storage::secret_exists(&self.database_path, &id)? {
                        return Err(anyhow!("secret `{id}` does not exist"));
                    }
                    deduped.insert(id);
                }

                let request = PendingRequest {
                    id: session.next_request_id,
                    requester,
                    reason: reason.unwrap_or_default(),
                    created_at: OffsetDateTime::now_utc()
                        .format(&Rfc3339)
                        .context("failed to format request timestamp")?,
                    secret_ids: deduped.into_iter().collect(),
                };
                session.next_request_id += 1;
                session.pending_requests.insert(request.id, request.clone());

                Ok(Response::RequestCreated { request })
            }
            Request::RequestsList => {
                let session = self
                    .session
                    .as_ref()
                    .ok_or_else(|| anyhow!("no shared session exists"))?;
                Ok(Response::RequestsList {
                    requests: session.pending_requests.values().cloned().collect(),
                })
            }
            Request::RequestsShow { request_id } => {
                let session = self
                    .session
                    .as_ref()
                    .ok_or_else(|| anyhow!("no shared session exists"))?;
                let request = session
                    .pending_requests
                    .get(&request_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("request `{request_id}` does not exist"))?;
                let numbered = request
                    .secret_ids
                    .iter()
                    .enumerate()
                    .map(|(index, id)| -> Result<RequestedSecret> {
                        let metadata = storage::get_secret_metadata(&self.database_path, id)?
                            .ok_or_else(|| anyhow!("secret `{id}` no longer exists"))?;
                        Ok(RequestedSecret {
                            index: index + 1,
                            metadata,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Response::RequestShow { request, numbered })
            }
            Request::RequestsApprove {
                request_id,
                selection,
            } => {
                let request = self
                    .session
                    .as_ref()
                    .ok_or_else(|| anyhow!("no shared session exists"))?
                    .pending_requests
                    .get(&request_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("request `{request_id}` does not exist"))?;
                let selected = select_requested_ids(&request.secret_ids, &selection)?;
                if selected.is_empty() {
                    return Err(anyhow!(
                        "approval selection did not match any requested secrets"
                    ));
                }
                biometric::authenticate("approve access to requested secrets")?;
                let key = keychain::load_vault_key()?;
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| anyhow!("no shared session exists"))?;
                session.pending_requests.remove(&request_id);
                session.unlocked_key = Some(key);
                session.approved_ids.extend(selected.iter().cloned());
                Ok(Response::Ack {
                    message: format!(
                        "approved {} secret(s) from request {}",
                        selected.len(),
                        request_id
                    ),
                })
            }
            Request::RequestsDeny {
                request_id,
                selection,
            } => {
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| anyhow!("no shared session exists"))?;
                if selection.is_none() {
                    session
                        .pending_requests
                        .remove(&request_id)
                        .ok_or_else(|| anyhow!("request `{request_id}` does not exist"))?;
                    return Ok(Response::Ack {
                        message: format!("denied request {request_id}"),
                    });
                }

                let selection = selection.unwrap();
                let request = session
                    .pending_requests
                    .get_mut(&request_id)
                    .ok_or_else(|| anyhow!("request `{request_id}` does not exist"))?;
                let denied = select_requested_ids(&request.secret_ids, &selection)?;
                request.secret_ids.retain(|id| !denied.contains(id));
                if request.secret_ids.is_empty() {
                    session.pending_requests.remove(&request_id);
                    return Ok(Response::Ack {
                        message: format!("denied request {request_id}"),
                    });
                }
                Ok(Response::Ack {
                    message: format!(
                        "denied {} secret(s) from request {}",
                        denied.len(),
                        request_id
                    ),
                })
            }
            Request::SecretsGet { id, fields } => {
                let session = self
                    .session
                    .as_ref()
                    .ok_or_else(|| anyhow!("no shared session exists"))?;
                if !session.approved_ids.contains(&id) {
                    return Err(anyhow!(
                        "secret `{id}` is not approved for the current session"
                    ));
                }
                let key = session.unlocked_key.as_ref().ok_or_else(|| {
                    anyhow!("shared session is locked; approve a request to unlock it")
                })?;
                let all_fields = storage::read_secret_fields(&self.database_path, &id, key)?;
                let requested_fields = select_fields(&all_fields, &fields)?;
                Ok(Response::SecretValues {
                    secret_id: id,
                    fields: requested_fields,
                })
            }
            Request::GrantsList => {
                let session = self
                    .session
                    .as_ref()
                    .ok_or_else(|| anyhow!("no shared session exists"))?;
                let grants = session
                    .approved_ids
                    .iter()
                    .map(|id| {
                        storage::get_secret_metadata(&self.database_path, id)?
                            .ok_or_else(|| anyhow!("approved secret `{id}` no longer exists"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Response::GrantsList { grants })
            }
        }
    }

    fn status(&self) -> SessionStatus {
        if let Some(session) = &self.session {
            SessionStatus {
                exists: true,
                unlocked: session.unlocked_key.is_some(),
                approved_ids: session.approved_ids.iter().cloned().collect(),
                pending_requests: session.pending_requests.keys().copied().collect(),
            }
        } else {
            SessionStatus {
                exists: false,
                unlocked: false,
                approved_ids: Vec::new(),
                pending_requests: Vec::new(),
            }
        }
    }

    fn load_key_for_management(&self) -> Result<Vec<u8>> {
        if let Some(session) = &self.session {
            if let Some(key) = &session.unlocked_key {
                return Ok(key.clone());
            }
        }
        biometric::authenticate("unlock the password vault")?;
        keychain::load_vault_key()
    }
}

// ---------------------------------------------------------------------------
// Selection helpers
// ---------------------------------------------------------------------------

fn select_requested_ids(requested: &[String], selection: &str) -> Result<BTreeSet<String>> {
    if selection == "all" {
        return Ok(requested.iter().cloned().collect());
    }

    let mut selected = BTreeSet::new();
    let indexes = parse_selection(selection, requested.len())?;
    for index in indexes {
        selected.insert(requested[index - 1].clone());
    }
    Ok(selected)
}

fn parse_selection(selection: &str, upper_bound: usize) -> Result<BTreeSet<usize>> {
    let mut picked = BTreeSet::new();
    for part in selection
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if let Some((start, end)) = part.split_once('-') {
            let start = parse_index(start, upper_bound)?;
            let end = parse_index(end, upper_bound)?;
            if start > end {
                return Err(anyhow!("invalid range `{part}`"));
            }
            for index in start..=end {
                picked.insert(index);
            }
        } else {
            picked.insert(parse_index(part, upper_bound)?);
        }
    }

    if picked.is_empty() {
        return Err(anyhow!("selection must not be empty"));
    }

    Ok(picked)
}

fn parse_index(raw: &str, upper_bound: usize) -> Result<usize> {
    let index = raw
        .parse::<usize>()
        .with_context(|| format!("failed to parse selection index `{raw}`"))?;
    if index == 0 || index > upper_bound {
        return Err(anyhow!(
            "selection index `{index}` is out of range 1..={upper_bound}"
        ));
    }
    Ok(index)
}

fn select_fields(
    all_fields: &Map<String, Value>,
    fields: &[String],
) -> Result<BTreeMap<String, String>> {
    let requested: Vec<String> = if fields.is_empty() {
        all_fields.keys().cloned().collect()
    } else {
        fields.to_vec()
    };

    let mut result = BTreeMap::new();
    for field in requested {
        let value = all_fields
            .get(&field)
            .ok_or_else(|| anyhow!("secret does not contain field `{field}`"))?;
        let value = match value {
            Value::String(value) => value.clone(),
            other => serde_json::to_string(other)
                .context("failed to serialize non-string secret field")?,
        };
        result.insert(field, value);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{parse_selection, select_requested_ids};

    #[test]
    fn parses_sparse_selection_ranges() {
        let selected = parse_selection("1,4,3-6", 6).unwrap();
        assert_eq!(selected, BTreeSet::from([1, 3, 4, 5, 6]));
    }

    #[test]
    fn approves_all_requested_ids() {
        let ids = vec!["github".to_string(), "slack".to_string()];
        let selected = select_requested_ids(&ids, "all").unwrap();
        assert_eq!(
            selected,
            BTreeSet::from(["github".to_string(), "slack".to_string()])
        );
    }
}
