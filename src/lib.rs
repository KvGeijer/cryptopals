use std::{
    collections::HashMap,
    error::Error,
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

    /// The smaller the more wordlike
    pub fn wordlike_score(&self) -> f64 {
        let json_freq = include_str!("./data/ascii_frec.json");
        let eng_freq_map: HashMap<char, f64> = serde_json::from_str(json_freq).unwrap();

        let mut counts: HashMap<char, usize> = HashMap::new();
        for byte in self.bytes.iter() {
            let char = byte.to_ascii_lowercase() as char;
            *counts.entry(char).or_insert(0) += 1;
        }

        let counted: usize = counts
            .iter()
            .filter_map(|(char, count)| eng_freq_map.contains_key(char).then_some(count))
            .sum();

        // I use the total variation difference between the distributions, as it is so simple
        // Really ugly adition to factor in spaces as there was one very similar without spaces... But basically cheating. Would want freq of spaces in dataset...
        let score = eng_freq_map
            .iter()
            .map(|(char, eng_freq)| {
                let obs_freq = *counts.get(char).unwrap_or(&0) as f64 / counted as f64;
                (eng_freq - obs_freq).abs()
            })
            .sum::<f64>()
            / counts
                .iter()
                .filter_map(|(char, count)| (char == &' ').then_some(*count as f64))
                .sum::<f64>();
        if score.is_nan() {
            f64::INFINITY
        } else {
            score
        }
    }

    pub fn to_utf8(&self) -> Result<String, Box<dyn Error>> {
        Ok(String::from_utf8(self.bytes.clone())?)
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
