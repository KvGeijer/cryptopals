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

    #[test]
    // Challenge 3
    fn single_byte_xor_cipher() {
        let input: ByteString =
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".into();

        // What char has it been xor'd against? Test all chars and choose the best result
        let best = (0..=(u8::MAX))
            .map(|xor_byte| input.bytewise_xor(xor_byte))
            .min_by(|a, b| a.wordlike_score().partial_cmp(&b.wordlike_score()).unwrap())
            .unwrap();

        assert_eq!(
            best.to_utf8().unwrap(),
            "Cooking MC's like a pound of bacon",
        );
    }
}
