use std::collections::HashMap;

use itertools::Itertools;
use rand::Rng;

use crate::{
    algorithms::aes::{aes_cbc_encrypt, aes_simple_decrypt, aes_simple_encrypt},
    bytestring::ByteString,
};

/// Has a secret key, and a secret string which it appends to all encryption calls
pub struct SimpleEcbAppender {
    key: Vec<u8>,
    secret_string: Vec<u8>,
}

impl SimpleEcbAppender {
    pub fn encrypt(&self, prepend: &[u8]) -> Vec<u8> {
        let mut input = prepend.to_vec();
        input.extend_from_slice(&self.secret_string);
        aes_simple_encrypt(&input, &self.key).unwrap()
    }

    pub fn new(bytes: &[u8]) -> Self {
        Self {
            key: random_bytes(16),
            secret_string: bytes.to_vec(),
        }
    }
}

pub fn debug_encryption_oracle(bytes: &[u8]) -> (Vec<u8>, bool) {
    let mut rng = rand::thread_rng();

    let mut input = random_bytes(rng.gen_range(5..=10));
    input.extend_from_slice(bytes);
    input.extend(random_bytes(rng.gen_range(5..=10)));

    let key = random_bytes(16);

    match rng.gen_bool(0.5) {
        true => (aes_simple_encrypt(&input, &key).unwrap(), true),
        false => (
            aes_cbc_encrypt(&input, &key, &random_bytes(16)).unwrap(),
            false,
        ),
    }
}

fn random_bytes(nbr: usize) -> Vec<u8> {
    (0..nbr).map(|_| rand::random()).collect()
}

pub struct EmailAdmin {
    key: Vec<u8>,
}

/// Splits entries at &, and key-values at =
fn kv_splitter(string: &str) -> Option<HashMap<String, String>> {
    string
        .split("&")
        .map(|entry| {
            entry
                .split("=")
                .into_iter()
                .map(|str| str.to_string())
                .tuples()
                .next()
        })
        .collect()
}

fn profile_for(email: &str) -> String {
    let address = email.replace("=", "::eq::").replace("&", "::and::");
    format!("email={address}&uid=10&role=user")
}

impl EmailAdmin {
    pub fn new() -> Self {
        Self {
            key: random_bytes(16),
        }
    }

    pub fn is_admin(&self, ciphertext: &[u8]) -> bool {
        if let Ok(Some(plaintext)) =
            aes_simple_decrypt(ciphertext, &self.key).map(|bytes| bytes.to_utf8())
        {
            kv_splitter(&plaintext)
                .map(|dict| dict.get("role") == Some(&"admin".to_owned()))
                .unwrap_or(false)
        } else {
            false
        }
    }

    pub fn encrypt_user(&self, plaintext: &str) -> Vec<u8> {
        let profile = profile_for(plaintext);
        aes_simple_encrypt(&profile.as_bytes(), &self.key).unwrap()
    }
}
