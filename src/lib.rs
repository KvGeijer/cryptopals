use std::{
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
        let bytes = string
            .iter()
            .tuples()
            .map(|(high, low)| (high << 4) + low)
            .collect();
        Self { bytes }
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
}

impl BitXor for ByteString {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let bytes = self
            .bytes
            .into_iter()
            .zip(rhs.bytes.into_iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect();
        Self { bytes }
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
