use std::collections::HashMap;

use itertools::Itertools;
use rand::Rng;

use crate::{
    algorithms::aes::{aes_cbc_decrypt, aes_cbc_encrypt, aes_simple_decrypt, aes_simple_encrypt},
    bytestring::ByteString,
};

/// Has a secret key, and a secret string which it appends to all encryption calls
pub struct EcbSurrounder {
    key: Vec<u8>,
    prepending: Vec<u8>,
    appending: Vec<u8>,
}

impl EcbSurrounder {
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut input = self.prepending.clone();
        input.extend_from_slice(plaintext);
        input.extend_from_slice(&self.appending);
        aes_simple_encrypt(&input, &self.key).unwrap()
    }

    pub fn new(prep_size: usize, appending: &[u8]) -> Self {
        Self {
            key: random_bytes(16),
            prepending: random_bytes(prep_size),
            appending: appending.to_vec(),
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

pub struct CbcSurrounder {
    key: Vec<u8>,
    init: Vec<u8>,
    prepending: Vec<u8>,
    appending: Vec<u8>,
}

impl CbcSurrounder {
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut input = self.prepending.clone();
        input.extend_from_slice(plaintext);
        input.extend_from_slice(&self.appending);
        aes_simple_encrypt(&input, &self.key).unwrap()
    }

    pub fn new(prepending: &str, appending: &str) -> Self {
        Self {
            key: random_bytes(16),
            init: random_bytes(16),
            prepending: prepending.as_bytes().to_vec(),
            appending: appending.as_bytes().to_vec(),
        }
    }

    /// Simplified to accept string where parts are not utf8
    pub fn is_admin(&self, ciphertext: &[u8]) -> bool {
        if let Ok(plaintext) = aes_cbc_decrypt(ciphertext, &self.key, &self.init) {
            println!("plaintext {:?}", plaintext);
            // Makes a lossy conversion, ignoring non-ascii chars, which is a bit of a stretch...
            let string = plaintext
                .into_iter()
                .flat_map(|byte| byte.is_ascii().then_some(byte as char))
                .collect::<String>();
            println!("string {:?}", string);
            return string.split(";").any(|split| split == "admin=true");
        }
        false
    }

    pub fn encrypt_user(&self, plaintext: &str) -> Vec<u8> {
        let mut input = self.prepending.clone();
        input.extend_from_slice(
            plaintext
                .replace("=", "::eq::")
                .replace(";", "::semicol::")
                .as_bytes(),
        );
        input.extend_from_slice(&self.appending);
        input = input.pad_pkcs7(16);

        aes_cbc_encrypt(&input, &self.key, &self.init).unwrap()
    }
}

pub struct CbcPaddingOracle {
    key: Vec<u8>,
    init: Vec<u8>,
}

impl CbcPaddingOracle {
    pub fn new() -> Self {
        Self {
            key: random_bytes(16),
            init: random_bytes(16),
        }
    }

    /// Encrypts the text under the oracle, adding padding.
    /// Returns the ciphertext as well as the initial vector used.
    pub fn encrypt(&self, plaintext: &[u8]) -> (Vec<u8>, &[u8]) {
        let ciphertext = aes_cbc_encrypt(&plaintext.pad_pkcs7(16), &self.key, &self.init)
            .expect("Should not crash with correct padding");
        (ciphertext, &self.init)
    }

    /// Decryps and returns whether the padding is valid or not
    pub fn check_padding(&self, ciphertext: &[u8]) -> bool {
        // This should only return err if padding invalid right?
        aes_cbc_decrypt(ciphertext, &self.key, &self.init)
            .unwrap()
            .remove_pkcs7_padding()
            .is_some()
    }
}
