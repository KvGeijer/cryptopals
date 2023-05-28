use std::collections::HashSet;

use crate::ByteString;

use itertools::Itertools;
use openssl::symm::{decrypt, encrypt, Cipher};

pub fn break_single_byte_xor_cipher(bytestring: &ByteString) -> Option<(ByteString, u8)> {
    let (_, decrypted, key) = (0..=(u8::MAX))
        .map(|xor_byte| (bytestring.bytewise_xor(xor_byte), xor_byte))
        .map(|(decrypted, xor_byte)| (decrypted.wordlike_score(), decrypted, xor_byte))
        .min_by(|(a, _, _), (b, _, _)| a.total_cmp(b))?;
    Some((decrypted, key))
}

/// Returns the decrypted input, and then the found key
pub fn break_repeating_bytes_xor_cipher(
    encrypted: &ByteString,
) -> Option<(ByteString, ByteString)> {
    let keysizes = find_keysizes_repeating_xor(encrypted, 4);
    let keys: Vec<ByteString> = find_keys_repeating_xor(encrypted, &keysizes)?;
    keys.into_iter()
        .map(|key| (encrypted.repeating_xor(key.as_slice()), key))
        .map(|(dec, key)| (dec, key))
        .min_by(|(a_dec, a_key), (b_dec, b_key)| {
            // want to slightly discourage longer keys, to avoid repeating keys
            let a_score = a_dec.wordlike_score() + a_key.as_slice().len() as f64 / 1000000.0;
            let b_score = b_dec.wordlike_score() + b_key.as_slice().len() as f64 / 1000000.0;
            a_score.total_cmp(&b_score)
        })
}

fn find_keysizes_repeating_xor(bytestring: &ByteString, nbr_wanted: usize) -> Vec<usize> {
    (2..=40)
        .flat_map(|keysize| {
            // Could skip this map and only use as sorting, but is a bit inefficient as we would calculate scores too often
            let chunks = 4;
            if bytestring.as_slice().len() > chunks * keysize {
                let score: u64 = bytestring
                    .as_slice()
                    .chunks(keysize)
                    .map(ByteString::from)
                    .take(chunks)
                    .permutations(2)
                    .map(|combs| combs[0].hamming_dist(&combs[1]))
                    .sum();

                Some((score as f64 / keysize as f64, keysize))
            } else {
                None
            }
        })
        .sorted_by(|(s1, _), (s2, _)| s1.total_cmp(s2))
        .map(|(_score, keysize)| keysize)
        .take(nbr_wanted)
        .collect()
}

fn find_keys_repeating_xor(bytestring: &ByteString, keysizes: &[usize]) -> Option<Vec<ByteString>> {
    keysizes
        .iter()
        .map(|&keysize| find_key_repeating_xor(bytestring, keysize))
        .collect::<Option<Vec<_>>>()
}

fn find_key_repeating_xor(bytestring: &ByteString, keysize: usize) -> Option<ByteString> {
    let blocks: Vec<&[u8]> = bytestring.as_slice().chunks(keysize).collect();
    Some(
        (0..keysize)
            .map(|ind| {
                // Solve transposed as single char xor cipher, to find that char of the key
                let (_score, key) = break_single_byte_xor_cipher(
                    &blocks
                        .iter()
                        .filter_map(|block| block.get(ind).cloned())
                        .collect::<Vec<u8>>()
                        .into(),
                )?;
                Some(key)
            })
            .collect::<Option<Vec<u8>>>()?
            .into(),
    )
}

/// Uses 128 bit ecb decryption
pub fn aes_simple_decrypt(bytes: &[u8], key: &[u8]) -> std::io::Result<ByteString> {
    Ok(decrypt(Cipher::aes_128_ecb(), key, None, bytes)?.into())
}

/// Uses 128 bit ecb encryption
pub fn aes_simple_encrypt(bytes: &[u8], key: &[u8]) -> std::io::Result<ByteString> {
    Ok(encrypt(Cipher::aes_128_ecb(), key, None, bytes)?.into())
}

pub fn aes_cbc_decrypt(bytes: &[u8], key: &[u8], init: &[u8]) -> std::io::Result<ByteString> {
    let mut prev: ByteString = init.into();
    let mut decrypted: ByteString = vec![].into();
    for encrypted_block in bytes.chunks(16).map(ByteString::from) {
        let mut padded_input = encrypted_block.clone();

        // Seems the ssl decrypt expexts this to be padded, as it crashes otherwise
        let encrypted_padding = aes_simple_encrypt(&[16; 16], key)?;
        padded_input.extend(&encrypted_padding);

        // Throw away the padding again... Why do we need this? I really don't understand
        let decrypted_block: ByteString =
            aes_simple_decrypt(&padded_input, key)?.as_slice()[..16].into();
        let decrypted_xord = decrypted_block.repeating_xor(&prev);

        decrypted.extend(&decrypted_xord);
        prev = encrypted_block;
    }
    Ok(decrypted.remove_pkcs7_padding())
}

pub fn aes_cbc_encrypt(bytes: &[u8], key: &[u8], init: &[u8]) -> std::io::Result<ByteString> {
    let mut prev: ByteString = init.into();
    let mut encrypted = vec![];

    for chunk in bytes.chunks(16).map(ByteString::from) {
        let output: ByteString =
            aes_simple_encrypt(&chunk.repeating_xor(&prev), key)?.as_slice()[..16].into();
        encrypted.extend(&output);
        prev = output;
    }
    Ok(encrypted.into())
}

/// How many 64 byte sequences are repeated?
///
/// ECB encryption don't use an initialization array, so every block (16 bytes)
/// will always be encoded to the same 16 encoded bytes. So if we have sequences
/// of 32 chars which are repeated (if ascii at least) we will notice duplicated
/// blocks in the encoded string as well.
///
/// This is not the case in most modes (not ECB) as they use a mutable initialization
/// vector which changes over time, removing this issue.
pub fn ecb_score(bytes: &[u8]) -> usize {
    bytes.chunks(16).count() - bytes.chunks(16).collect::<HashSet<_>>().len()
}

#[test]
fn test_aes_ecb() {
    let key = b"YELLOW SUBMARINE";
    let input = b"ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP";
    let encrypted = aes_simple_encrypt(input, key).unwrap();
    let decrypted = aes_simple_decrypt(&encrypted, key).unwrap();
    assert_eq!(input.as_ref(), decrypted.as_slice());
}

#[test]
fn test_aes_cbc() {
    let iv = [0; 16];
    let key = b"YELLOW SUBMARINE";
    let input = b"ABCDEFGHIJKLMNOP";
    let encrypted = aes_cbc_encrypt(input, key, &iv).unwrap();
    let decrypted = aes_cbc_decrypt(&encrypted, key, &iv).unwrap();
    assert_eq!(input.as_ref(), decrypted.as_slice());
}
