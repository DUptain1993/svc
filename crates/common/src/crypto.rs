use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;

pub fn seal_with_key(key: &[u8; 32], plaintext: &[u8]) -> String {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).expect("aead");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    STANDARD.encode(out)
}

pub fn seal(plaintext: &[u8]) -> String {
    let key = crate::envkey::runtime_exfil_key();
    seal_with_key(&key, plaintext)
}

pub fn seal_str(s: &str) -> String {
    seal(s.as_bytes())
}

pub fn open(key: &[u8; 32], b64: &str) -> Option<Vec<u8>> {
    let blob = STANDARD.decode(b64).ok()?;
    if blob.len() < 12 + 16 { return None; }
    let (nonce_bytes, ct) = blob.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    cipher.decrypt(Nonce::from_slice(nonce_bytes), ct).ok()
}
