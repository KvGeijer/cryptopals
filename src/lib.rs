#[macro_use]
extern crate lazy_static;

use std::{
    collections::HashMap,
    fmt::{self, Display},
    ops::BitXor,
};

use itertools::Itertools;

#[derive(Clone)]
pub struct ByteString {
    pub bytes: Vec<u8>,
}

impl ByteString {
    pub fn from_hexadecimal_str(hex_str: &str) -> Self {
        let hexes: Vec<u8> = hex_str
            .chars()
            .map(|char| char.to_digit(16).expect("Could not parse char as radix 16") as u8)
            .collect();
        Self::from_u4_string(&hexes)
    }

    pub fn from_u4_string(string: &[u8]) -> Self {
        string
            .iter()
            .tuples()
            .map(|(high, low)| (high << 4) + low)
            .collect::<Vec<_>>()
            .into()
    }

    /// Coverts a string of u8 to one of u24
    pub fn to_u24_string(&self) -> Vec<u32> {
        self.bytes
            .chunks(3)
            .map(|chunk| {
                chunk
                    .iter()
                    .zip([2, 1, 0])
                    .map(|(&byte, shift)| (byte as u32) << (shift * 8))
                    .sum()
            })
            .collect()
    }

    pub fn to_u6_string(&self) -> Vec<u8> {
        self.to_u24_string()
            .into_iter()
            .flat_map(|sword| {
                [3, 2, 1, 0]
                    .into_iter()
                    .map(move |shift| ((sword >> (6 * shift)) & 0b111111) as u8)
            })
            .collect()
    }

    pub fn as_base64(&self) -> String {
        let base64_chars: Vec<char> =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                .chars()
                .collect();
        self.to_u6_string()
            .into_iter()
            .map(|ind| base64_chars[ind as usize])
            .collect()
    }

    pub fn as_base4(&self) -> String {
        self.bytes
            .iter()
            .flat_map(|byte| [(byte >> 4) & 0b1111, byte & 0b1111])
            .map(|hex| char::from_digit(hex as u32, 16).unwrap())
            .collect()
    }

    pub fn bytewise_xor(&self, xor_byte: u8) -> Self {
        self.bytes
            .iter()
            .map(|&byte| byte ^ xor_byte)
            .collect::<Vec<_>>()
            .into()
    }

    pub fn repeating_xor(&self, key: &[u8]) -> Self {
        self.bytes
            .chunks(3)
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .cloned()
                    .zip(key.iter().cloned())
                    .collect::<Vec<_>>()
            })
            .map(|(byte, xor_byte)| byte ^ xor_byte)
            .collect::<Vec<_>>()
            .into()
    }

    /// The smaller the more wordlike
    pub fn wordlike_score(&self) -> f64 {
        // The data taken from https://raw.githubusercontent.com/piersy/ascii-char-frequency-english/main/ascii_freq.json
        // But has been reformatted to a nice dictionary
        lazy_static! {
            static ref ENG_FREQS: HashMap<u8, f64> = {
                let json_freq = include_str!("./data/large_ascii_freq.json");
                serde_json::from_str(json_freq).unwrap()
            };
        }

        let mut counts: HashMap<u8, usize> = HashMap::new();
        for byte in self.bytes.iter() {
            *counts.entry(*byte).or_insert(0) += 1;
        }

        // I use the total variation difference between the distributions, as it is so simple
        let score = ENG_FREQS
            .iter()
            .map(|(char, eng_freq)| {
                // bytes.len() should be close to correct
                let obs_freq = *counts.get(char).unwrap_or(&0) as f64 / self.bytes.len() as f64;
                (eng_freq - obs_freq).abs()
            })
            .sum::<f64>();

        if score.is_nan() {
            f64::INFINITY
        } else {
            score
        }
    }

    pub fn to_utf8(&self) -> Option<String> {
        String::from_utf8(self.bytes.clone()).ok()
    }
}

impl BitXor for ByteString {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.bytes
            .into_iter()
            .zip(rhs.bytes.into_iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect::<Vec<_>>()
            .into()
    }
}

impl Display for ByteString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = self
            .bytes
            .iter()
            .map(|byte| format!("{:08b}", byte))
            .join("");
        write!(f, "{string}")
    }
}

impl From<&str> for ByteString {
    fn from(string: &str) -> Self {
        Self::from_hexadecimal_str(string)
    }
}

impl From<Vec<u8>> for ByteString {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl From<&[u8]> for ByteString {
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}
