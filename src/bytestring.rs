use std::collections::HashMap;

use itertools::Itertools;

// Only uses functional style streaming, which can be ineffective (could add a mutable trait for vec)
pub trait ByteString {
    // fn from_hexadecimal_str(hex_str: &str) -> Vec<u8>;

    fn as_base64(&self) -> String;

    fn as_base4_str(&self) -> String;

    fn repeating_xor(&self, key: &[u8]) -> Vec<u8>;

    /// The smaller the more wordlike
    fn wordlike_score(&self) -> f64;

    fn to_utf8(&self) -> Option<String>;

    fn hamming_dist(&self, other: &Self) -> u64;

    /// Pads the bytes to a multiple of the blocksize.
    ///
    /// The padding bytes has the value of the number of such bytes added, as in pkcs.
    /// If alrealy multiple, adds a whole block of padding.
    fn pad_pkcs7(&self, blocksize: usize) -> Vec<u8>;

    /// If there is pkcs at the end, removes those paddings
    fn remove_pkcs7_padding(&self) -> Vec<u8>;

    fn extend_slice(&self, bytes: &[u8]) -> Vec<u8>;
}

impl ByteString for [u8] {
    fn as_base64(&self) -> String {
        self.chunks(3)
            .map(|chunk| {
                chunk
                    .iter()
                    .zip([2, 1, 0])
                    .map(|(&byte, shift)| (byte as u32) << (shift * 8))
                    .sum()
            })
            .flat_map(|u24: u32| {
                (0..=3)
                    .rev()
                    .map(move |shift| ((u24 >> (6 * shift)) & 0b111111) as u8)
            })
            .map(|u6| BASE64_CHARS[u6 as usize])
            .collect()
    }

    fn as_base4_str(&self) -> String {
        self.iter()
            .flat_map(|byte| [(byte >> 4) & 0b1111, byte & 0b1111])
            .map(|hex| char::from_digit(hex as u32, 16).unwrap())
            .collect()
    }

    fn repeating_xor(&self, key: &[u8]) -> Vec<u8> {
        self.iter()
            .zip(key.iter().cycle())
            .map(|(byte, xor_byte)| byte ^ xor_byte)
            .collect()
    }

    fn wordlike_score(&self) -> f64 {
        // The data taken from https://raw.githubusercontent.com/piersy/ascii-char-frequency-english/main/ascii_freq.json
        // But has been reformatted to a nice dictionary
        lazy_static! {
            static ref ENG_FREQS: HashMap<char, f64> = {
                let json_freq = include_str!("../character_statistics/frankenstein_freqs.json");
                serde_json::from_str(json_freq).unwrap()
            };
        }

        let mut counts: HashMap<char, usize> = HashMap::new();
        for byte in self.iter() {
            *counts.entry(*byte as char).or_insert(0) += 1;
        }
        let common_counted: usize = ENG_FREQS
            .iter()
            .filter_map(|(char, _)| counts.get(char))
            .sum();

        // I use the total variation difference between the distributions, as it is so simple
        let score = ENG_FREQS
            .iter()
            .map(|(char, eng_freq)| {
                // bytes.len() should be close to correct
                let obs_freq = *counts.get(char).unwrap_or(&0) as f64 / common_counted as f64;
                (eng_freq - obs_freq).abs()
            })
            .sum::<f64>();

        if score.is_nan() {
            f64::INFINITY
        } else {
            score
        }
    }

    fn to_utf8(&self) -> Option<String> {
        String::from_utf8(self.to_vec()).ok()
    }

    fn hamming_dist(&self, other: &Self) -> u64 {
        self.iter()
            .zip(other)
            .map(|(b1, b2)| (b1 ^ b2).count_ones() as u64)
            .sum()
    }

    fn pad_pkcs7(&self, blocksize: usize) -> Vec<u8> {
        let padding_size = blocksize - (self.len() % blocksize);
        let mut vec = self.to_vec();
        vec.extend_from_slice(&[padding_size as u8; 32][..padding_size]);
        vec
    }

    fn remove_pkcs7_padding(&self) -> Vec<u8> {
        if let Some(&last) = self.last() {
            if last < 32 {
                self[..self.len() - last as usize].into()
            } else {
                self.to_vec()
            }
        } else {
            self.to_vec()
        }
    }

    fn extend_slice(&self, bytes: &[u8]) -> Vec<u8> {
        let mut vec = self.to_vec();
        vec.extend_from_slice(bytes);
        vec
    }
}

lazy_static! {
    static ref BASE64_CHARS: Vec<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .chars()
            .collect();
    static ref BASE64_CHAR_INDS: HashMap<char, usize> =
        BASE64_CHARS.iter().cloned().zip(0..).collect();
}

/// Does not correctly handle = padding at the end...
pub fn from_base64_str(base64_str: &str) -> Option<Vec<u8>> {
    let mut u6_inds = base64_str
        .chars()
        .filter(|char| *char != '=')
        .map(|char| BASE64_CHAR_INDS.get(&char).map(|ind| *ind as u8))
        .collect::<Option<Vec<u8>>>()?;

    let padding_count = base64_str.chars().rev().take_while(|&c| c == '=').count();
    u6_inds.resize(u6_inds.len() + padding_count, 0);

    let mut decoded = u6_inds
        .chunks(4) // 4 6 bit bytes => 24 bits = 3 bytes
        .map(|chunk| {
            // to 24 bit u32
            chunk.iter().fold(0u32, |acc, u6| (acc << 6) + (*u6 as u32))
        })
        .flat_map(|u24| (0..=2).map(move |shift| ((u24 >> (16 - shift * 8)) & 0b11111111) as u8))
        .collect::<Vec<u8>>();

    // This is not correct.
    decoded.truncate(decoded.len() - padding_count);

    Some(decoded)
}

pub fn from_hex_str(hex_str: &str) -> Option<Vec<u8>> {
    Some(
        hex_str
            .chars()
            .map(|char| char.to_digit(16).map(|byte| byte as u8))
            .collect::<Option<Vec<u8>>>()?
            .into_iter()
            .tuples()
            .map(|(high, low)| (high << 4) + low)
            .collect(),
    )
}

// impl BitXor for dyn ByteString {
//     type Output = Self;

//     fn bitxor(self, rhs: Self) -> Self::Output {
//         self.bytes
//             .into_iter()
//             .zip(rhs.bytes.into_iter())
//             .map(|(lhs, rhs)| lhs ^ rhs)
//             .collect::<Vec<_>>()
//             .into()
//     }
// }

// impl Display for ByteString {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let string = self
//             .bytes
//             .iter()
//             .map(|byte| format!("{:08b}", byte))
//             .join("");
//         write!(f, "{string}")
//     }
// }

// impl From<&str> for ByteString {
//     fn from(string: &str) -> Self {
//         Self::from_hexadecimal_str(string)
//     }
// }
