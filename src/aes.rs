use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use blake2::Blake2b512;
use digest::Digest;
use erreur::*;
use serde::{Deserialize, Serialize};

use crate::rng::fill_random;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, Default)]
// 保留协议消息类型使用的标准密码学缩写。
#[allow(clippy::upper_case_acronyms)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
    pub aad: Vec<u8>,
}

pub fn aes_encrypt(key: &[u8], pt: &[u8]) -> Resultat<AEAD> {
    let mut aes_key = [255u8; 32];
    let end = std::cmp::min(32, key.len());
    aes_key[..end].copy_from_slice(&key[..end]);
    let aes_key: &Key<Aes256Gcm> = &aes_key.into();
    let cipher = Aes256Gcm::new(aes_key);
    let aad = Blake2b512::digest(pt).to_vec();

    let mut nonce = [0u8; 12];
    fill_random(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let payload = Payload { msg: pt, aad: &aad };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .ok()
        .ifnone("AesGcmEncryptFailed", "AES-GCM encrypt")?;

    Ok(AEAD {
        ciphertext,
        tag: nonce.to_vec(),
        aad,
    })
}

pub fn aes_decrypt(key: &[u8], ct: &AEAD) -> Resultat<Vec<u8>> {
    let mut aes_key = [255u8; 32];
    let end = std::cmp::min(32, key.len());
    aes_key[..end].copy_from_slice(&key[..end]);
    let aes_key: &Key<Aes256Gcm> = &aes_key.into();
    let cipher = Aes256Gcm::new(aes_key);

    let nonce = Nonce::from_slice(&ct.tag);
    let payload = Payload {
        msg: ct.ciphertext.as_slice(),
        aad: &ct.aad,
    };

    let out = cipher.decrypt(nonce, payload).ok().ifnone(
        "AesGcmDecryptFailed",
        "AES-GCM decrypt; wrong password or nonce",
    )?;

    let ha = Blake2b512::digest(&out).to_vec();
    assert_throw!(ha == ct.aad, "AesDecryptIntegrity", "message broken");
    Ok(out)
}
