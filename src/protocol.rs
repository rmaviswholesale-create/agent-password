use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::storage::SecretMetadata;

// Variant names mirror the CLI command tree (`secrets request` →
// SecretsRequest), so the overlap with the enum name is intentional.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    VaultInit,
    SessionCreate {
        replace: bool,
    },
    SessionStatus,
    SessionClose,
    SessionClear,
    SecretPut {
        id: String,
        kind: String,
        title: Option<String>,
        service: Option<String>,
        username: Option<String>,
        tags: Vec<String>,
        fields: Map<String, Value>,
    },
    SecretDelete {
        id: String,
    },
    SecretsList,
    SecretShow {
        id: String,
    },
    SecretsRequest {
        ids: Vec<String>,
        requester: String,
        reason: Option<String>,
    },
    RequestsList,
    RequestsShow {
        request_id: u64,
    },
    RequestsApprove {
        request_id: u64,
        selection: String,
    },
    RequestsDeny {
        request_id: u64,
        selection: Option<String>,
    },
    SecretsGet {
        id: String,
        fields: Vec<String>,
    },
    GrantsList,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ack {
        message: String,
    },
    SessionStatus {
        status: SessionStatus,
    },
    SecretsList {
        secrets: Vec<SecretMetadata>,
    },
    SecretShow {
        secret: SecretMetadata,
    },
    RequestCreated {
        request: PendingRequest,
    },
    RequestsList {
        requests: Vec<PendingRequest>,
    },
    RequestShow {
        request: PendingRequest,
        numbered: Vec<RequestedSecret>,
    },
    SecretValues {
        secret_id: String,
        fields: BTreeMap<String, String>,
    },
    GrantsList {
        grants: Vec<SecretMetadata>,
    },
    Error {
        message: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionStatus {
    pub exists: bool,
    pub unlocked: bool,
    pub approved_ids: Vec<String>,
    pub pending_requests: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingRequest {
    pub id: u64,
    pub requester: String,
    pub reason: String,
    pub created_at: String,
    pub secret_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestedSecret {
    pub index: usize,
    pub metadata: SecretMetadata,
}

#[derive(Debug, Default)]
pub struct SessionState {
    /// Vault key held in daemon memory while the session is unlocked.
    /// Zeroizing guarantees the bytes are wiped when the session is
    /// closed, cleared, or replaced.
    pub unlocked_key: Option<zeroize::Zeroizing<Vec<u8>>>,
    pub approved_ids: BTreeSet<String>,
    pub pending_requests: BTreeMap<u64, PendingRequest>,
    pub next_request_id: u64,
}
