use base64::{engine::general_purpose, Engine as _};

use cryptopals::ByteString;

fn real_decrypt_base64(string: &str) -> ByteString {
    general_purpose::STANDARD.decode(string).unwrap().into()
}

fn main() {
    let string = include_str!("../tests/data/challenge-1-6.txt")
        .lines()
        .collect::<String>();
    let bytestring = real_decrypt_base64(&string);

    let key = b"Terminator X: Bring the noise";
    let decrypted = bytestring.repeating_xor(key);

    println!("{}", decrypted.to_utf8().unwrap());
}
