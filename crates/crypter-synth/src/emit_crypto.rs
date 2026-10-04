use crypter_ir::DecryptScheme;

pub fn emit_crypto_for(scheme: &DecryptScheme) -> String {
    let mut s = String::new();
    match scheme {
        DecryptScheme::AesGcm => {
            s.push_str(AES_GCM_CODE);
        }
        DecryptScheme::ChaCha20Poly1305 => {
            s.push_str(CHACHA_CODE);
        }
        DecryptScheme::AesCbcHmac => {
            s.push_str(AES_GCM_CODE);
            s.push_str(AES_CBC_HMAC_CODE);
        }
        DecryptScheme::XorDerived => {}
    }
    s.push('\n');
    s
}

const AES_GCM_CODE: &str = r#"
fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8], ct_in: &[u8], out: &mut [u8]) -> Result<(), ()> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    if nonce.len() != 12 || ct_in.len() < 16 { return Err(()); }
    let cipher = Aes256Gcm::new(key.into());
    let pt = cipher.decrypt(Nonce::from_slice(nonce), ct_in).map_err(|_| ())?;
    if pt.len() != out.len() { return Err(()); }
    out.copy_from_slice(&pt);
    Ok(())
}
"#;

const CHACHA_CODE: &str = r#"
fn chacha_decrypt(key: &[u8; 32], nonce: &[u8], ct_in: &[u8], out: &mut [u8]) -> Result<(), ()> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    if nonce.len() != 12 || ct_in.len() < 16 { return Err(()); }
    let cipher = ChaCha20Poly1305::new(key.into());
    let pt = cipher.decrypt(Nonce::from_slice(nonce), ct_in).map_err(|_| ())?;
    if pt.len() != out.len() { return Err(()); }
    out.copy_from_slice(&pt);
    Ok(())
}
"#;

const AES_CBC_HMAC_CODE: &str = r#"
fn aes_cbc_hmac_decrypt(_key: &[u8; 32], _iv: &[u8], _mac: &[u8], _ct: &[u8], _out: &mut [u8]) -> Result<(), ()> {
    Err(())
}
"#;
