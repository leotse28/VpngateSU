//! Small byte helpers ported from the JS reference (u16/u32 big-endian,
//! Internet checksum). No external dependencies.

pub fn u16be(b: &[u8], o: usize) -> u16 {
    ((b[o] as u16) << 8) | (b[o + 1] as u16)
}

pub fn u32be(b: &[u8], o: usize) -> u32 {
    ((b[o] as u32) << 24) | ((b[o + 1] as u32) << 16) | ((b[o + 2] as u32) << 8) | (b[o + 3] as u32)
}

/// Internet checksum (IPv4 header / TCP pseudo-header), as in the JS `csum`.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16be(data, i) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    (!sum) as u16
}

/// Random bytes from the OS (used for UUIDs, source ports, TCP ISNs).
pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Random UUID v4, formatted, as used for the SSTP correlation ID.
pub fn random_uuid() -> String {
    let b = random_bytes(16);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6] & 0x0f, b[7], (b[8] & 0x3f) | 0x80, b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_vector() {
        // IPv4 header of a 20-byte header with zero checksum field:
        // 45 00 00 28 00 00 40 00 40 06 00 00 C0 A8 00 01 C0 A8 00 02
        let hdr = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0x02,
        ];
        // Known-good checksum for this header is 0xB970.
        assert_eq!(checksum(&hdr), 0xB97C);
        // Verifying: checksum over header with checksum inserted must be 0.
        let mut h2 = hdr.to_vec();
        h2[10] = 0xB9;
        h2[11] = 0x7C;
        assert_eq!(checksum(&h2), 0);
    }

    #[test]
    fn uuid_format() {
        let u = random_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[8..9], "-");
        assert_eq!(&u[14..15], "4");
    }
}
