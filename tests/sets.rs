use cryptopals::ByteString;

#[test]
fn challenge_1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let output = ByteString::from_hexadecimal_str(input).to_base64();
    // println!("{output}");
    assert_eq!(
        output,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}
