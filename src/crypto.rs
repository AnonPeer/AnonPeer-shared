use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use chacha20poly1305::aead::Aead;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::RngCore;
use x25519_dalek::{StaticSecret, PublicKey};
use crate::errors::AnonError;

pub fn hash_password(password: &str) -> Result<String, AnonError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let ph = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AnonError::Crypto(format!("Argon2: {e}")))?;
    Ok(ph.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, AnonError> {
    let ph = PasswordHash::new(hash)
        .map_err(|e| AnonError::Crypto(format!("Parse: {e}")))?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &ph).is_ok())
}

pub fn generate_ed25519_keys() -> (Vec<u8>, Vec<u8>) {
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let verifying_key = signing_key.verifying_key();
    (signing_key.to_bytes().to_vec(), verifying_key.to_bytes().to_vec())
}

pub fn generate_x25519_keys() -> (Vec<u8>, Vec<u8>) {
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let secret = StaticSecret::from(sk_bytes);
    let public = PublicKey::from(&secret);
    (secret.to_bytes().to_vec(), public.to_bytes().to_vec())
}

pub fn derive_chat_key(my_secret: &[u8], peer_public: &[u8]) -> Result<Vec<u8>, AnonError> {
    let s: [u8; 32] = my_secret.try_into()
        .map_err(|_| AnonError::Crypto("Invalid secret len".into()))?;
    let p: [u8; 32] = peer_public.try_into()
        .map_err(|_| AnonError::Crypto("Invalid public len".into()))?;
    let shared = StaticSecret::from(s).diffie_hellman(&PublicKey::from(p));
    Ok(shared.to_bytes().to_vec())
}

pub fn encrypt_sign(
    plaintext: &[u8],
    chacha_key: &[u8],
    ed_secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), AnonError> {
    let key = chacha20poly1305::Key::from_slice(chacha_key);
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| AnonError::Crypto(format!("Enc: {e}")))?;
    let sk = SigningKey::from_bytes(
        ed_secret
            .try_into()
            .map_err(|_| AnonError::Crypto("Bad sk len".into()))?,
    );
    let signature = sk.sign(&ciphertext).to_bytes().to_vec();
    Ok((ciphertext, nonce.to_vec(), signature, vec![]))
}

pub fn decrypt_verify(
    ciphertext: &[u8],
    nonce: &[u8],
    signature: &[u8],
    chacha_key: &[u8],
    ed_public: &[u8],
) -> Result<Vec<u8>, AnonError> {
    if !ed_public.is_empty() && ed_public.len() == 32 && signature.len() == 64 {
        if let Ok(sig) = Signature::from_slice(signature) {
            if let Ok(vk) = VerifyingKey::from_bytes(ed_public.try_into().unwrap()) {
                vk.verify(ciphertext, &sig)
                    .map_err(|_| AnonError::Crypto("Bad signature".into()))?;
            }
        }
    }
    let key = chacha20poly1305::Key::from_slice(chacha_key);
    let cipher = ChaCha20Poly1305::new(key);
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| AnonError::Crypto(format!("Dec: {e}")))
}