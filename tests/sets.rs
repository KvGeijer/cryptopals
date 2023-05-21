use cryptopals::ByteString;

mod set_1 {
    use super::*;

    #[test]
    // Challenge 1
    fn hex_to_base64() {
        let input: ByteString = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".into();
        let output = input.as_base64();
        assert_eq!(
            output,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    // Challenge 2
    fn fixed_xor() {
        let left: ByteString = "1c0111001f010100061a024b53535009181c".into();
        let right: ByteString = "686974207468652062756c6c277320657965".into();
        let xor = left ^ right;
        assert_eq!(&xor.as_base4(), "746865206b696420646f6e277420706c6179")
    }

    fn best_xor_cipher(bytestring: &ByteString) -> (f64, ByteString) {
        (0..=(u8::MAX))
            .map(|xor_byte| bytestring.bytewise_xor(xor_byte))
            .map(|decrypted| (decrypted.wordlike_score(), decrypted))
            .min_by(|(a, _), (b, _)| a.partial_cmp(b).unwrap())
            .unwrap()
    }

    #[test]
    // Challenge 3
    fn single_byte_xor_cipher() {
        let input: ByteString =
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".into();

        // What char has it been xor'd against? Test all chars and choose the best result
        let (_score, best) = best_xor_cipher(&input);

        assert_eq!(
            best.to_utf8().unwrap(),
            "Cooking MC's like a pound of bacon",
        );
    }

    #[test]
    // Challenge 4
    fn detect_single_byte_xor() {
        let bytestrings: Vec<ByteString> = include_str!("./data/challenge-1-4.txt")
            .lines()
            .map(ByteString::from_hexadecimal_str)
            .collect();

        let (_improvement, decrypted) = bytestrings
            .iter()
            .map(|bytestring| {
                let original_score = bytestring.wordlike_score();
                let (decrypted_score, decrypted_string) = best_xor_cipher(bytestring);
                (original_score / decrypted_score, decrypted_string)
            })
            .max_by(|(a, _), (b, _)| a.partial_cmp(b).unwrap())
            .unwrap();

        assert_eq!(
            decrypted.to_utf8().unwrap(),
            "Now that the party is jumping\n",
        );
    }

    #[test]
    // Challenge 5
    fn repeating_key_xor() {
        let input: ByteString =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .as_bytes()
                .into();
        let key = "ICE".as_bytes();

        let decrypted = input.repeating_xor(key);

        assert_eq!(
            decrypted.as_base4(),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }
}
