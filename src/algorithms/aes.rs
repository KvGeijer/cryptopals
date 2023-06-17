use std::collections::HashSet;

use crate::{
    bytestring::ByteString,
    oracles::aes::{EcbSurrounder, EmailAdmin},
};

use itertools::Itertools;
use openssl::symm::{decrypt, encrypt, Cipher};

/// Uses 128 bit ecb decryption
pub fn aes_simple_decrypt(bytes: &[u8], key: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(decrypt(Cipher::aes_128_ecb(), key, None, bytes)?)
}

/// Uses 128 bit ecb encryption
pub fn aes_simple_encrypt(bytes: &[u8], key: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(encrypt(Cipher::aes_128_ecb(), key, None, bytes)?)
}

pub fn aes_cbc_decrypt(bytes: &[u8], key: &[u8], init: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut prev = init;
    let mut decrypted = vec![];
    for encrypted_block in bytes.chunks(16) {
        let mut padded_input = encrypted_block.to_vec();

        // Seems the ssl decrypt expexts this to be padded, as it crashes otherwise
        let encrypted_padding = aes_simple_encrypt(&[16; 16], key)?;
        padded_input.extend(&encrypted_padding);

        // Throw away the padding again... Why do we need this? I really don't understand. Sort of get it, but annoying
        let mut decrypted_block = aes_simple_decrypt(&padded_input, key)?;
        decrypted_block.truncate(16);
        let decrypted_xord = decrypted_block.repeating_xor(prev);

        decrypted.extend(&decrypted_xord);
        prev = encrypted_block;
    }

    Ok(decrypted)
}

pub fn aes_cbc_encrypt(bytes: &[u8], key: &[u8], init: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut prev = init.to_vec();
    let mut encrypted = vec![];
    for plain_block in bytes.chunks(16) {
        let mut output = aes_simple_encrypt(&plain_block.repeating_xor(&prev), key)?;
        output.truncate(16);
        encrypted.extend(&output);
        prev = output;
    }

    Ok(encrypted)
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

pub fn break_ecb_surrounding_oracle(oracle: &EcbSurrounder) -> Result<Vec<u8>, String> {
    const MAX_BLOCKSIZE: usize = 32;
    const MAX_ZEROBLOCK: [u8; 3 * MAX_BLOCKSIZE] = [0; 3 * MAX_BLOCKSIZE];
    // Step 1: establish block size, by finding which block just adds an extra block
    let init_len = oracle.encrypt(b"").len();
    let blocksize = (1..=MAX_BLOCKSIZE)
        .find_map(|blocksize| {
            let new_len = &oracle.encrypt(&MAX_ZEROBLOCK[..blocksize]).len();
            let diff_len = new_len - init_len;
            (diff_len != 0).then_some(diff_len)
        })
        .ok_or_else(|| "Could not find a blocksize".to_string())?;
    assert_eq!(blocksize, 16);

    // Step 2: Assert that it is ECB mode. Make sure you get one extra repeating block
    let init_score = ecb_score(&oracle.encrypt(&MAX_ZEROBLOCK[1..blocksize]));
    let padded_score = ecb_score(&oracle.encrypt(&MAX_ZEROBLOCK[1..3 * blocksize]));
    if init_score + 1 != padded_score {
        return Err(format!(
            "The oracle is not using ecb. Got scores {} and {}, with blocksize {}",
            init_score, padded_score, blocksize
        ));
    }

    // Step 3: Find the size of the prepended padding
    // See in which blocks the prepadding is, by seeing the first one we can modify
    const MAX_ONEBLOCK: [u8; 3 * MAX_BLOCKSIZE] = [1; 3 * MAX_BLOCKSIZE];
    let zero_enc = oracle.encrypt(&MAX_ZEROBLOCK[..blocksize]);
    let one_enc = oracle.encrypt(&MAX_ONEBLOCK[..blocksize]);
    let padding_blocks = zero_enc
        .chunks(blocksize)
        .zip(one_enc.chunks(blocksize))
        .take_while(|(zero, one)| zero == one)
        .count();

    // Then see how far into the next block the prepending string stretches
    let padding_fill = blocksize
        - (1..=MAX_BLOCKSIZE)
            .find_map(|fillsize| {
                // The two blocks after the prepend + fillsize padding. Should be identical if correct fillsize
                let zero_corr_blocks = oracle.encrypt(&MAX_ZEROBLOCK[..2 * blocksize + fillsize])
                    [(padding_blocks + 1) * blocksize..(padding_blocks + 3) * blocksize]
                    .to_vec();
                // Test for 0 and 1 to make sure it was not a fluke and to do with appending matching 0s
                let one_corr_blocks = oracle.encrypt(&MAX_ONEBLOCK[..2 * blocksize + fillsize])
                    [(padding_blocks + 1) * blocksize..(padding_blocks + 3) * blocksize]
                    .to_vec();

                // Adding some filling and two whole blocks should give an ecb score of one for the
                // two blocks following the prepend and filled padding [prep1, ... [prep_last + fillsize], [corr1], [corr2]]
                (ecb_score(&zero_corr_blocks) == 1 && ecb_score(&one_corr_blocks) == 1)
                    .then_some(fillsize)
            })
            .expect("Could not find a fillsize");

    // The padding to add to the plaintext to get a clean cut at a multiple of padd
    let padding_vec = MAX_ZEROBLOCK[..blocksize - padding_fill].to_vec();
    let prepad_len = blocksize * (padding_blocks + 1); // Pad out the last block to a clean one

    // Step 4 Breaking: Now we do a one byte lookup at a time to find the secret
    let mut decrypted = vec![0; blocksize];
    for (block, padding) in (0..).cartesian_product((0..blocksize).rev()) {
        // The blocksize -1 bytes in front of the next inspected byte
        let known = decrypted[(decrypted.len() - blocksize + 1)..].to_vec();
        assert_eq!(known.len(), blocksize - 1);

        // The block we would have got where the expected byte is the last one, and we know the rest
        let mut input = padding_vec.clone();
        input.extend_from_slice(&MAX_ZEROBLOCK[..padding]);
        let expected_block = oracle.encrypt(&input)
            [prepad_len + (block * blocksize)..prepad_len + ((block + 1) * blocksize)]
            .to_vec();

        // Now find the byte which produces the same block when added to the last known bytes
        let mut input = padding_vec.clone();
        input.extend_from_slice(&known);
        input.push(0);
        if let Some(decrypted_byte) = (0..=u8::MAX).find(|&byte| {
            let last_ind = input.len() - 1;
            input[last_ind] = byte;
            let faked_block = oracle.encrypt(&input)[prepad_len..prepad_len + blocksize].to_vec();
            assert_eq!(faked_block.len(), expected_block.len());
            faked_block == expected_block
        }) {
            decrypted.push(decrypted_byte);
        } else {
            break;
        };
    }
    Ok(decrypted[blocksize..].to_vec())
}

pub fn forge_admin_ciphertext(oracle: &EmailAdmin) -> Vec<u8> {
    // We will just assume it is ecb and blocksize 16
    const BLOCKSIZE: usize = 16;

    // f"email={email}&uid=10&role=user"

    // Strategy: want to find a way to see what block admin would be parsed to
    // Then swap out last block, only containing the role in a valid user profile

    // Has to be of length 13 + 16k
    let email = "daru@twipo.jp";
    let mut ciphertext = oracle.encrypt_user(email).as_slice().to_vec();

    assert_eq!(ciphertext.len(), BLOCKSIZE * 3);

    // Make email=0123456789 be the first block, and admin be the second (with valid padding), and just grab the second block
    let admin_input_block = "admin".as_bytes().pad_pkcs7(BLOCKSIZE).to_utf8().unwrap();
    let admin_input = format!("0123456789{admin_input_block}");
    let manipulated_ciphertext = oracle.encrypt_user(&admin_input).as_slice().to_vec();
    let admin_block = &manipulated_ciphertext[BLOCKSIZE..2 * BLOCKSIZE];

    ciphertext[2 * BLOCKSIZE..].copy_from_slice(admin_block);
    assert_eq!(ciphertext.len(), BLOCKSIZE * 3);

    ciphertext
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
