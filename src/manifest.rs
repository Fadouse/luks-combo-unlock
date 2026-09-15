// SPDX-License-Identifier: GPL-3.0-only
use crate::{Result, crypto, fail};
const MAGIC: &[u8; 8] = b"LCUV2\0\0\0";
pub struct Manifest {
    pub uuid: String,
    pub salt: [u8; 32],
    pub public_key: [u8; 64],
    pub cid: Vec<u8>,
}
impl Manifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(&MAGIC[..]);
        out.extend_from_slice(self.uuid.as_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&(self.cid.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.cid);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 143 || &bytes[..8] != MAGIC {
            return Err(fail("invalid v2 manifest"));
        }
        let len = u16::from_be_bytes(bytes[140..142].try_into()?) as usize;
        if len == 0 || len > 1024 || bytes.len() != 142 + len {
            return Err(fail("invalid credential length"));
        }
        let uuid = std::str::from_utf8(&bytes[8..44])?.to_owned();
        validate_uuid(&uuid)?;
        Ok(Self {
            uuid,
            salt: bytes[44..76].try_into()?,
            public_key: bytes[76..140].try_into()?,
            cid: bytes[142..].to_vec(),
        })
    }
    pub fn digest(&self) -> String {
        crypto::hex(&crypto::hash(&self.encode()))
    }
    pub fn challenge(&self) -> Result<[u8; 32]> {
        let mut data = b"luks-combo-unlock/v2/assertion\0".to_vec();
        data.extend_from_slice(&crypto::hash(&self.encode()));
        let mut nonce = [0; 32];
        crypto::random(&mut nonce)?;
        data.extend_from_slice(&nonce);
        Ok(crypto::hash(&data))
    }
}
pub fn validate_uuid(uuid: &str) -> Result<()> {
    if uuid.len() != 36
        || !uuid.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    {
        return Err(fail("invalid LUKS UUID"));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_is_exact_and_challenges_are_fresh() {
        let m = Manifest {
            uuid: "12345678-1234-4234-8234-123456789abc".into(),
            salt: [1; 32],
            public_key: [2; 64],
            cid: vec![3; 64],
        };
        let data = m.encode();
        assert_eq!(Manifest::decode(&data).unwrap().encode(), data);
        for n in 0..data.len() {
            assert!(Manifest::decode(&data[..n]).is_err());
        }
        let mut extra = data.clone();
        extra.push(0);
        assert!(Manifest::decode(&extra).is_err());
        assert_ne!(m.challenge().unwrap(), m.challenge().unwrap());
    }
}
