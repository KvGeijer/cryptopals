#![feature(ascii_char)]

use cryptopals::ByteString;
use itertools::Itertools;

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

    fn best_xor_cipher(bytestring: &ByteString) -> (f64, ByteString, u8) {
        (0..=(u8::MAX))
            .map(|xor_byte| (bytestring.bytewise_xor(xor_byte), xor_byte))
            .map(|(decrypted, xor_byte)| (decrypted.wordlike_score(), decrypted, xor_byte))
            .min_by(|(a, _, _), (b, _, _)| a.partial_cmp(b).unwrap())
            .unwrap()
    }

    #[test]
    // Challenge 3
    fn single_byte_xor_cipher() {
        let input: ByteString =
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".into();

        // What char has it been xor'd against? Test all chars and choose the best result
        let (_score, best, _key) = best_xor_cipher(&input);

        assert_eq!(
            best.to_utf8().unwrap(),
            "Cooking MC's like a pound of bacon",
        );
    }

    #[test]
    // #[ignore] // Takes a second to run
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
                let (decrypted_score, decrypted_string, _key) = best_xor_cipher(bytestring);
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

    #[test]
    fn hamming_distance() {
        let test: ByteString = "this is a test".as_bytes().into();
        let wokka: ByteString = "wokka wokka!!!".as_bytes().into();

        assert_eq!(test.hamming_dist(&wokka), 37);
    }

    #[test]
    // Reverse test from challenge 1, needed for challenge 6
    fn from_base64() {
        let input = ByteString::from_base64(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        )
        .unwrap();
        let output = input.as_base4();
        assert_eq!(
            output,
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        );
    }

    /// Returns the decrypted input, and then the found key
    fn break_repeating_key_xor(encrypted: &ByteString) -> (ByteString, ByteString) {
        // sort_by direkt på keysizes
        let mut keysize_scores: Vec<(f64, usize)> = (2..=40)
            .map(|keysize| {
                let chunks = 4;
                let score: u64 = encrypted
                    .as_slice()
                    .chunks(keysize)
                    .map(ByteString::from)
                    .take(chunks)
                    .permutations(2)
                    .map(|combs| combs[0].hamming_dist(&combs[1]))
                    .sum();

                (score as f64 / keysize as f64, keysize)
            })
            .collect();

        keysize_scores.sort_by(|(score1, _), (score2, _)| score1.partial_cmp(score2).unwrap());
        // println! {"{:?}", keysize_scores};
        let potential_keysizes = keysize_scores.into_iter().map(|(_, size)| size).take(40); // Does not work when taking fewer

        let keys: Vec<ByteString> = potential_keysizes
            .map(|keysize| {
                let blocks: Vec<&[u8]> = encrypted.as_slice().chunks(keysize).collect();
                let transposed = (0..keysize).map(|ind| {
                    blocks
                        .iter()
                        .filter_map(|block| block.get(ind).cloned())
                        .collect::<Vec<u8>>()
                });

                // Solve transposed as single char xor cipher, to find that char of the key
                transposed
                    .map(|block| best_xor_cipher(&block.into()).2)
                    .collect::<Vec<u8>>()
                    .into()
            })
            .collect();

        for key in keys.iter() {
            let decoded = encrypted.repeating_xor(key.as_slice());
            println!(
                "{:?}, {:?}, {}\n-----------------------------------------",
                decoded
                    .as_slice()
                    .iter()
                    .filter_map(|u8| u8.is_ascii().then_some(*u8 as char))
                    .collect::<String>(),
                key.as_slice()
                    .iter()
                    .filter_map(|u8| u8.is_ascii().then_some(*u8 as char))
                    .collect::<String>(),
                key.as_slice().len()
            );
        }

        keys.into_iter()
            .map(|key| (encrypted.repeating_xor(key.as_slice()), key))
            .min_by(|(a_dec, a_key), (b_dec, b_key)| {
                // want to slightly discourage longer keys, to avoid repeating keys
                let a_score = a_dec.wordlike_score() + a_key.as_slice().len() as f64 / 1000.0;
                let b_score = b_dec.wordlike_score() + b_key.as_slice().len() as f64 / 1000.0;
                a_score.partial_cmp(&b_score).unwrap()
            })
            .unwrap()
    }

    #[test]
    fn cancelling_repeating_key_xor() {
        let input: ByteString = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".into();
        let key = "ICE".as_bytes();
        assert_eq!(input, input.repeating_xor(key).repeating_xor(key));
    }

    #[test]
    // #[ignore]
    fn breaking_simple_repeating_key_xor() {
        let input: ByteString = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".into();
        let (decrypted, key) = break_repeating_key_xor(&input);

        let expected =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

        assert_eq!(decrypted.to_utf8().unwrap(), expected);
        assert_eq!(key.to_utf8().unwrap(), "ICE");
    }

    #[test]
    // #[ignore]
    // Challenge 6
    fn breaking_repeating_key_xor() {
        let bytestring = ByteString::from_base64(
            &include_str!("./data/challenge-1-6.txt")
                .lines()
                .collect::<String>(),
        )
        .unwrap();

        let (_decrypted, key) = break_repeating_key_xor(&bytestring);
        println!(
            "{:?}, {}",
            // decrypted
            //     .as_slice()
            //     .iter()
            //     .filter_map(|u8| u8.is_ascii().then_some(*u8 as char))
            //     .collect::<String>(),
            key.as_slice()
                .iter()
                .filter_map(|u8| u8.is_ascii().then_some(*u8 as char))
                .collect::<String>(),
            key.as_slice().len()
        );
        // println!("{:?}, {:?}", decrypted.to_utf8(), key.to_utf8());
        todo!();
    }
}
