use cryptopals::{
    algorithms::aes::{
        self, aes_cbc_decrypt, aes_cbc_encrypt, bitflip_cbc_admin, break_ecb_surrounding_oracle,
        ecb_score, forge_admin_ciphertext,
    },
    bytestring::{from_base64_str, ByteString},
    oracles::aes::{debug_encryption_oracle, CbcSurrounder, EcbSurrounder, EmailAdmin},
};

#[test]
fn pkcs_padding() {
    let input = b"YELLOW SUBMARINE";

    assert_eq!(
        input.pad_pkcs7(20).to_utf8().unwrap(),
        "YELLOW SUBMARINE\x04\x04\x04\x04"
    );
}

#[test]
fn ecb_fixed_point() {
    let key = b"YELLOW SUBMARINE";
    let input = b"testtesttesttesttesttesttesttest1234567890123456uneven";

    let encrypted = aes::aes_simple_encrypt(input, key).unwrap();
    let decrypted = aes::aes_simple_decrypt(&encrypted, key).unwrap();

    assert_eq!(input.as_slice(), decrypted.as_slice());
}

#[test]
// Challenge 10
fn cbc_decryption() {
    let bytes = from_base64_str(
        &include_str!("data/challenge-10.txt")
            .lines()
            .collect::<String>(),
    )
    .unwrap();

    let key = b"YELLOW SUBMARINE";
    let initial = [0; 16];

    let expected = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
    let decrypted = aes::aes_cbc_decrypt(&bytes, key, &initial)
        .unwrap()
        .remove_pkcs7_padding()
        .unwrap()
        .to_utf8()
        .unwrap();

    assert_eq!(expected, decrypted);
}

#[test]
// Challenge 11
fn detect_encryption_oracle() {
    let input = [b'A'; 64];
    for _ in 1..10 {
        let (enc, ecb) = debug_encryption_oracle(&input);
        assert_eq!(ecb, ecb_score(&enc) > 1);
    }
}

#[test]
// Challenge 12
fn simple_byte_at_a_time() {
    let secret = from_base64_str(
        &include_str!("./data/challenge-12.txt")
            .lines()
            .collect::<String>(),
    )
    .unwrap();

    let oracle = EcbSurrounder::new(0, &secret);

    let decrypted = break_ecb_surrounding_oracle(&oracle)
        .unwrap()
        .remove_pkcs7_padding()
        .unwrap();

    assert_eq!(decrypted, secret);
    assert_eq!(decrypted.to_utf8().unwrap(), "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n");
}

#[test]
// Challenge 13
fn ecb_cp() {
    // So the idea is that we can send in an email and get the ecb encrypted ciphertext for
    // f"email={email}&uid=\d\d&role=user"
    // We can also send in a ciphertext and get back a bool of if it can be decrypted to f"role=admin"
    // So we want to exploit ecb to craft a ciphertext that would be a valid admin profile
    let oracle = EmailAdmin::new();
    let admin_cipher = forge_admin_ciphertext(&oracle);
    assert!(oracle.is_admin(&admin_cipher));
}

#[test]
// Challenge 14
fn harder_byte_at_a_time() {
    let secret = from_base64_str(
        &include_str!("./data/challenge-12.txt")
            .lines()
            .collect::<String>(),
    )
    .unwrap();

    // Test a few number around edges of blocks
    for prep_size in [1, 15, 17, 51, 63, 64, 65] {
        let oracle = EcbSurrounder::new(prep_size, &secret);

        let decrypted = break_ecb_surrounding_oracle(&oracle)
            .unwrap()
            .remove_pkcs7_padding()
            .unwrap();

        assert_eq!(decrypted, secret);
        assert_eq!(decrypted.to_utf8().unwrap(), "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n");
    }
}

#[test]
// Challenge 15
fn pkcs7_validation() {
    assert_eq!(
        b"ICE ICE BABY\x04\x04\x04\x04"
            .remove_pkcs7_padding()
            .unwrap(),
        b"ICE ICE BABY"
    );

    assert!(b"ICE ICE BABY\x05\x05\x05\x05"
        .remove_pkcs7_padding()
        .is_none());
}

#[test]
fn simple_cbc_bitflipping() {
    // Just to see if I understand how to solve challenge 16
    let plaintext = "fillerfillerfil\nSome real messa\nffffffffffff\x04\x04\x04\x04";

    // It will only bitflip the corresponding bits in the immediately proceeding block. Not all of the following ones, which is nice.
    let expexted = "Qome real messa\nffffffffffff\x04\x04\x04\x04";

    let key = b"1234098745671209";
    let init = [0; 16];

    let mut ciphertext = aes_cbc_encrypt(plaintext.as_bytes(), key, &init).unwrap();

    ciphertext[0] = ciphertext[0] ^ 2;

    let decrypted = aes_cbc_decrypt(&ciphertext, key, &init).unwrap();
    assert_eq!(decrypted[16..].to_utf8().unwrap(), expexted);
}

#[test]
// Challenge 16
fn cbc_bitflipping() {
    let prep = "comment1=cooking%20MCs;userdata=";
    let oracle = CbcSurrounder::new(prep, ";comment2=%20like%20a%20pound%20of%20bacon");

    let admin_ciphertext = bitflip_cbc_admin(&oracle, prep.len());

    assert!(oracle.is_admin(&admin_ciphertext));
}
