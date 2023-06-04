use rand::Rng;

use crate::algorithms::aes::{aes_cbc_encrypt, aes_simple_encrypt};

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
