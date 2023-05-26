#[macro_use]
extern crate lazy_static;

use std::{
    collections::HashMap,
    fmt::{self, Display},
    ops::{self, BitXor, Deref},
};

use itertools::Itertools;

pub mod algorithms;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteString {
    bytes: Vec<u8>,
}

lazy_static! {
    static ref BASE64_CHARS: Vec<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .chars()
            .collect();
    static ref BASE64_CHAR_INDS: HashMap<char, usize> =
        BASE64_CHARS.iter().cloned().zip(0..).collect();
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

    /// Does not correctly handle = padding at the end...
    pub fn from_base64(base64_str: &str) -> Option<Self> {
        let mut u6_inds = base64_str
            .chars()
            .filter(|char| *char != '=')
            .map(|char| BASE64_CHAR_INDS.get(&char).map(|ind| *ind as u8))
            .collect::<Option<Vec<u8>>>()?;

        let padding_count = base64_str.chars().rev().take_while(|&c| c == '=').count();
        u6_inds.resize(u6_inds.len() + padding_count, 0);

        let mut decoded: ByteString = u6_inds
            .chunks(4) // 4 6 bit bytes => 24 bits = 3 bytes
            .map(|chunk| {
                // to 24 bit u32
                chunk.iter().fold(0u32, |acc, u6| (acc << 6) + (*u6 as u32))
            })
            .flat_map(|u24| {
                (0..=2).map(move |shift| ((u24 >> (16 - shift * 8)) & 0b11111111) as u8)
            })
            .collect::<Vec<u8>>()
            .into();

        // This is not correct.
        decoded.bytes.truncate(decoded.bytes.len() - padding_count);

        Some(decoded)
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
        self.to_u6_string()
            .into_iter()
            .map(|ind| BASE64_CHARS[ind as usize])
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
            .iter()
            .zip(key.iter().cycle())
            .map(|(byte, xor_byte)| byte ^ xor_byte)
            .collect::<Vec<_>>()
            .into()
    }

    /// The smaller the more wordlike
    pub fn wordlike_score(&self) -> f64 {
        // The data taken from https://raw.githubusercontent.com/piersy/ascii-char-frequency-english/main/ascii_freq.json
        // But has been reformatted to a nice dictionary
        lazy_static! {
            static ref ENG_FREQS: HashMap<char, f64> = {
                let json_freq = include_str!("../character_statistics/frankenstein_freqs.json");
                serde_json::from_str(json_freq).unwrap()
            };
        }

        let mut counts: HashMap<char, usize> = HashMap::new();
        for byte in self.bytes.iter() {
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

    pub fn to_utf8(&self) -> Option<String> {
        String::from_utf8(self.bytes.clone()).ok()
    }

    pub fn hamming_dist(&self, other: &Self) -> u64 {
        self.bytes
            .iter()
            .zip(other.as_slice())
            .map(|(b1, b2)| (b1 ^ b2).count_ones() as u64)
            .sum()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Pads the bytes to a multiple of the blocksize.
    ///
    /// The padding bytes has the value of the number of such bytes added, as in pkcs.
    pub fn pad_pkcs7(mut self, blocksize: usize) -> Self {
        let padding_size = (blocksize - (self.bytes.len() % blocksize)) % blocksize;
        for _padding in 0..padding_size {
            self.bytes.push(padding_size as u8);
        }
        self
    }
}

impl<'a> IntoIterator for &'a ByteString {
    type Item = &'a u8;
    type IntoIter = std::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.bytes.iter()
    }
}

impl ops::Index<ops::Range<usize>> for ByteString {
    type Output = [u8];

    fn index(&self, range: ops::Range<usize>) -> &[u8] {
        &self.bytes[range]
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

impl AsRef<[u8]> for ByteString {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl Deref for ByteString {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}
