use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientPayload {
    Register { 
        username: String, 
        password: String, 
        ed_public: Vec<u8>, 
        x25519_public: Vec<u8> 
    },
    Login { 
        username: String, 
        password: String, 
        ed_public: Vec<u8>, 
        x25519_public: Vec<u8> 
    },
    SendMessage { msg: AppMessage },
    RequestKeys { target: String }, 
    SearchUser { username: String },
    SearchPrefix { prefix: String },
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
    pub from: String,
    pub to: String,
    pub timestamp: u64,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
    pub salt: Vec<u8>,
}