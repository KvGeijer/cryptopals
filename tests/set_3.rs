use cryptopals::{
    algorithms::aes::padding_validation_sidechannel,
    bytestring::{from_base64_str, ByteString},
    oracles::aes::CbcPaddingOracle,
};

#[test]
// Challenge 17
fn cbc_padding_oracle() {
    let strings: Vec<Vec<u8>> = include_str!("data/challenge-17.txt")
        .lines()
        .map(from_base64_str)
        .collect::<Option<_>>()
        .unwrap();

    let oracle = CbcPaddingOracle::new();
    for plaintext in strings {
        let (ciphertext, iv) = oracle.encrypt(&plaintext);
        let decrypted = padding_validation_sidechannel(&ciphertext, iv, &oracle);
        println!(
            "{:?}",
            decrypted.remove_pkcs7_padding().unwrap().to_utf8().unwrap()
        );
        assert_eq!(plaintext.pad_pkcs7(16), decrypted);
    }
}
