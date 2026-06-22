extern crate alloc;
use alloc::vec::Vec;

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn escape(input: &[u8], out: &mut Vec<u8>) {
    for &b in input {
        match b {
            b'*' | b'(' | b')' | b'\\' | 0 => {
                out.push(b'\\');
                out.push(HEX[(b >> 4) as usize]);
                out.push(HEX[(b & 0x0F) as usize]);
            }
            _ => out.push(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    #[test]
    fn escape_plain_ascii_passes_through() {
        let mut out = Vec::new();
        escape(b"alice", &mut out);
        assert_eq!(out, b"alice");
    }

    #[test]
    fn escape_star_becomes_2a() {
        let mut out = Vec::new();
        escape(b"a*b", &mut out);
        assert_eq!(out, b"a\\2ab");
    }

    #[test]
    fn escape_paren_and_backslash_and_null() {
        let mut out = Vec::new();
        escape(b"(\\\0", &mut out);
        assert_eq!(out, b"\\28\\5c\\00");
    }
}
