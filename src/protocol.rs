use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub nickname: String,
    pub username: String,
    #[serde(default)]
    pub bio: String,
    #[serde(default)]
    pub avatar_base64: Option<String>,
    #[serde(default)]
    pub server_domain: Option<String>,
    #[serde(default)]
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text(String),
    Image { mime_type: String, base64_data: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientPayload {
    Register { 
        nickname: String, 
        username: String, 
        password: String, 
        ed_public: Vec<u8>, 
        x25519_public: Vec<u8> 
    },
    Login { username: String, password: String, ed_public: Vec<u8>, x25519_public: Vec<u8> },
    SendMessage { msg: AppMessage },
    RequestKeys { target: String },
    SearchPrefix { prefix: String },
    ValidateSession { session_id: String },
    Federate { from_server: String, msg: AppMessage },
    RequestProfile { username: String },
    UpdateProfile { bio: Option<String>, avatar_base64: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerPayload {
    AuthOk { session_id: String },
    AuthErr(String),
    Forward { msg: AppMessage },
    PeerKeys { target: String, ed_public: Vec<u8>, x25519_public: Vec<u8> },
    SearchResults { matches: Vec<UserInfo> }, 
    ProfileResult { user: Option<UserInfo> },
    ProfileUpdated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMessage {
    pub id: Uuid,
    pub from: String,
    pub to: String,   
    pub timestamp: u64,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
    pub salt: Vec<u8>,
}