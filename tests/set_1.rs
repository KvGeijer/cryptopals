use cryptopals::{
    algorithms::{aes, xor},
    bytestring::{from_base64_str, from_hex_str, ByteString},
};

#[test]
// Challenge 1
fn hex_to_base64() {
    let input = from_hex_str("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    let output = input.as_base64();
    assert_eq!(
        output,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}

#[test]
// Challenge 2
fn fixed_xor() {
    let left = from_hex_str("1c0111001f010100061a024b53535009181c").unwrap();
    let right = from_hex_str("686974207468652062756c6c277320657965").unwrap();
    let xor = left.repeating_xor(&right);
    assert_eq!(&xor.as_base4_str(), "746865206b696420646f6e277420706c6179")
}

#[test]
// Challenge 3
fn single_byte_xor_cipher() {
    let input =
        from_hex_str("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();

    // What char has it been xor'd against? Test all chars and choose the best result
    let (best, _key) = xor::break_single_byte_xor_cipher(&input).unwrap();

    assert_eq!(
        best.to_utf8().unwrap(),
        "Cooking MC's like a pound of bacon",
    );
}

#[test]
#[ignore]
// Challenge 4
fn detect_single_byte_xor() {
    let byteslist: Vec<Vec<u8>> = include_str!("./data/challenge-4.txt")
        .lines()
        .map(from_hex_str)
        .collect::<Option<_>>()
        .unwrap();

    let (_improvement, decrypted) = byteslist
        .iter()
        .map(|bytes| {
            let original_score = bytes.wordlike_score();
            let (decrypted, _key) = xor::break_single_byte_xor_cipher(bytes).unwrap();
            (original_score / decrypted.wordlike_score(), decrypted)
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
    let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE".as_bytes();

    let decrypted = input.repeating_xor(key);

    assert_eq!(
        decrypted.as_base4_str(),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );
}

#[test]
fn hamming_distance() {
    let test = b"this is a test";
    let wokka = b"wokka wokka!!!";

    assert_eq!(test.hamming_dist(wokka), 37);
}

#[test]
// Reverse test from challenge 1, needed for challenge 6
fn from_base64() {
    let input = from_base64_str("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
        .unwrap();
    let output = input.as_base4_str();
    assert_eq!(
        output,
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    );
}

#[test]
#[ignore]
// This is from earlier challenge, but as the key is so short it becomes hard to solve
fn breaking_simple_repeating_key_xor() {
    let input_str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    let input_bytes = from_hex_str(input_str).unwrap();
    let (decrypted, _key) = xor::break_repeating_bytes_xor_cipher(&input_bytes).unwrap();

    let expected = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    assert_eq!(decrypted.to_utf8().unwrap(), expected);
}

#[test]
// #[ignore]
// Challenge 6
fn breaking_repeating_key_xor() {
    let bytes = from_base64_str(
        &include_str!("./data/challenge-6.txt")
            .lines()
            .collect::<String>(),
    )
    .unwrap();

    let (decrypted, key) = xor::break_repeating_bytes_xor_cipher(&bytes).unwrap();
    let expected = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
    assert_eq!(key.to_utf8().unwrap(), "Terminator X: Bring the noise");
    assert_eq!(decrypted.to_utf8().unwrap(), expected.to_string());
}

#[test]
// Challenge 7
fn using_openssl_aes() {
    let key = b"YELLOW SUBMARINE";
    let encrypted = from_base64_str(
        &include_str!("data/challenge-7.txt")
            .lines()
            .collect::<String>(),
    )
    .unwrap();

    let decrypted = aes::aes_simple_decrypt(&encrypted, key).unwrap();
    let expected = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

    assert_eq!(expected, decrypted.to_utf8().unwrap());
}

#[test]
// Challenge 8
fn detect_ecb() {
    let (line, _bytes) = include_str!("data/challenge-8.txt")
        .lines()
        .map(|line| from_hex_str(line).unwrap())
        .enumerate()
        .max_by_key(|(_, bytes)| aes::ecb_score(bytes))
        .unwrap();

    assert_eq!(line, 132);
}
