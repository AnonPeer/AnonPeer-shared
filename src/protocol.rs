use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text(String),
    Image { mime_type: String, base64_data: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientPayload {
    Register { username: String, password: String, ed_public: Vec<u8>, x25519_public: Vec<u8> },
    Login { username: String, password: String, ed_public: Vec<u8>, x25519_public: Vec<u8> },
    SendMessage { msg: AppMessage },
    RequestKeys { target: String },
    SearchUser { username: String },
    SearchPrefix { prefix: String },
    ValidateSession { session_id: String },
    Federate { from_server: String, msg: AppMessage }, 
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerPayload {
    AuthOk { session_id: String },
    AuthErr(String),
    Forward { msg: AppMessage },
    PeerKeys {  
        target: String, 
        ed_public: Vec<u8>, 
        x25519_public: Vec<u8> 
    },
    UserSearchResult { username: String, exists: bool },
    SearchResults { matches: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMessage {
    pub id: Uuid,
    // Теперь from и to могут быть в формате "user" или "user@domain.com"
    pub from: String, 
    pub to: String,
    pub timestamp: u64,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
    pub salt: Vec<u8>,
}