use base64::{engine::general_purpose, Engine as _};
use cryptopals::bytestring::ByteString;

fn real_decrypt_base64(string: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(string).unwrap()
}

fn main() {
    let string = include_str!("../tests/data/challenge-6.txt")
        .lines()
        .collect::<String>();
    let bytestring = real_decrypt_base64(&string);

    let key = b"Terminator X: Bring the noise";
    let decrypted = bytestring.repeating_xor(key);

    println!("{}", decrypted.to_utf8().unwrap());
}
