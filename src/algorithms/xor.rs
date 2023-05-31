use crate::bytestring::ByteString;

use itertools::Itertools;

pub fn break_single_byte_xor_cipher(bytes: &[u8]) -> Option<(Vec<u8>, u8)> {
    let (_, decrypted, key) = (0..=(u8::MAX))
        .map(|xor_byte| (bytes.repeating_xor(&[xor_byte]), xor_byte))
        .map(|(decrypted, xor_byte)| (decrypted.wordlike_score(), decrypted, xor_byte))
        .min_by(|(a, _, _), (b, _, _)| a.total_cmp(b))?;
    Some((decrypted, key))
}

/// Returns the decrypted input, and then the found key
pub fn break_repeating_bytes_xor_cipher(encrypted: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let keysizes = find_keysizes_repeating_xor(encrypted, 4);
    let keys: Vec<Vec<u8>> = find_keys_repeating_xor(encrypted, &keysizes)?;
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

fn find_keysizes_repeating_xor(bytes: &[u8], nbr_wanted: usize) -> Vec<usize> {
    (2..=40)
        .flat_map(|keysize| {
            // Could skip this map and only use as sorting, but is a bit inefficient as we would calculate scores too often
            let chunks = 4;
            if bytes.len() > chunks * keysize {
                let score: u64 = bytes
                    .chunks(keysize)
                    .take(chunks)
                    .permutations(2)
                    .map(|combs| combs[0].hamming_dist(combs[1]))
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

fn find_keys_repeating_xor(bytes: &[u8], keysizes: &[usize]) -> Option<Vec<Vec<u8>>> {
    keysizes
        .iter()
        .map(|&keysize| find_key_repeating_xor(bytes, keysize))
        .collect::<Option<Vec<_>>>()
}

fn find_key_repeating_xor(bytes: &[u8], keysize: usize) -> Option<Vec<u8>> {
    let blocks: Vec<&[u8]> = bytes.chunks(keysize).collect();
    (0..keysize)
        .map(|ind| {
            // Solve transposed as single char xor cipher, to find that char of the key
            let (_score, key) = break_single_byte_xor_cipher(
                &blocks
                    .iter()
                    .filter_map(|block| block.get(ind).cloned())
                    .collect::<Vec<u8>>(),
            )?;
            Some(key)
        })
        .collect::<Option<Vec<u8>>>()
}
