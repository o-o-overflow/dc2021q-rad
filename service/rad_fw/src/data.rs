//! Memory integrity and recovery.

use crate::array::BigArray;
use crate::{RadError, RAD_PUB_KEY};
use rad_common::MAX_MESSAGE_SIZE;
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::hash::Hasher;

pub const MAX_MODULE_SIZE: usize = 2usize.pow(12);
pub const MODULE_UPDATE_THRESHOLD: u64 = 300;
pub const SIGNATURE_SIZE: usize = 64;

lazy_static! {
    // TODO: Make this x84_64 code for fun?
    static ref ROOT_SEED: [u64; 4] = [
        0x67678957519dcf38,
        0xb3a247b1d038f570,
        0x3a1c737b3e72f2a4,
        0xd383f84a00e3300f,
    ];

    static ref ENCODER: ReedSolomon = ReedSolomon::new(2, 1).expect("u64 encoder");
}

/// Repairable trait.
pub trait Repairable {
    /// Verify data integrity, returning true if it is intact.
    fn verify(&self) -> Result<bool, RadError>;

    /// Attempt to repair the data.
    fn repair(&mut self) -> Result<(), RadError>;
}

pub fn hash(data: &[u8]) -> Result<u64, RadError> {
    Ok(seahash::State::hash(
        data,
        (ROOT_SEED[0], ROOT_SEED[1], ROOT_SEED[2], ROOT_SEED[3]),
    )
    .finalize())
}

pub fn hasher() -> Result<seahash::SeaHasher, RadError> {
    Ok(seahash::SeaHasher::with_seeds(
        ROOT_SEED[0],
        ROOT_SEED[1],
        ROOT_SEED[2],
        ROOT_SEED[3],
    ))
}

/// Critical u64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct U64 {
    data: [[u8; 4]; 3],
    checksum: u64,
}

impl U64 {
    /// Initialize the data.
    pub fn new(data: u64) -> Result<Self, RadError> {
        let mut x = Self {
            data: [[0u8; 4], [0u8; 4], [0u8; 4]],
            checksum: 0,
        };
        x.update(data)?;
        Ok(x)
    }

    /// Return the data.
    pub fn get(&mut self) -> Result<u64, RadError> {
        if !self.verify()? {
            self.repair()?;
        }
        let mut data = [0u8; 8];
        data[..4].copy_from_slice(&self.data[0]);
        data[4..].copy_from_slice(&self.data[1]);
        Ok(u64::from_be_bytes(data))
    }

    /// Update the data.
    pub fn update(&mut self, data: u64) -> Result<(), RadError> {
        let data = data.to_be_bytes();
        self.data[0].copy_from_slice(&data[..4]);
        self.data[1].copy_from_slice(&data[4..]);
        ENCODER.encode(&mut self.data)?;
        let mut state = hasher()?;
        state.write(&self.data[0]);
        state.write(&self.data[1]);
        state.write(&self.data[2]);
        self.checksum = state.finish();
        Ok(())
    }

    /// Increment the data.
    pub fn increment(&mut self, n: u64) -> Result<(), RadError> {
        let x = self.get()?;
        self.update(x + n)
    }
}

impl Repairable for U64 {
    fn verify(&self) -> Result<bool, RadError> {
        let mut state = hasher()?;
        state.write(&self.data[0]);
        state.write(&self.data[1]);
        state.write(&self.data[2]);
        Ok(self.checksum == state.finish())
    }

    fn repair(&mut self) -> Result<(), RadError> {
        let data = self.data;
        for i in 0..data.len() {
            let mut shards: Vec<Option<_>> = data.iter().map(|x| Some(x.to_vec())).collect();
            shards[i] = None;
            ENCODER.reconstruct(&mut shards)?;
            for (xs, shard) in self.data.iter_mut().zip(shards) {
                let shard = shard.ok_or_else(|| RadError::Repair("empty shard".to_string()))?;
                xs.copy_from_slice(&shard[..4]);
            }
            if self.verify()? {
                debug!("repaired u64 at {:#?}", self.data.as_ptr());
                return Ok(());
            }
        }
        Err(RadError::Repair("unable to repair u64".to_string()))
    }
}

/// Critical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bytes<const N: usize> {
    pub(crate) data: [[u8; N]; 3],
    pub(crate) checksum: u64,
}

impl<const N: usize> Bytes<N> {
    /// Initialize the data.
    pub fn new(data: &[u8]) -> Result<Self, RadError> {
        let mut x = Self {
            data: [[0u8; N], [0u8; N], [0u8; N]],
            checksum: 0,
        };
        x.update(data)?;
        Ok(x)
    }

    /// Return the current data.
    pub fn get(&mut self, buffer: &mut [u8]) -> Result<(), RadError> {
        if buffer.len() != N * 2 {
            return Err(RadError::Data(
                "invalid byte vector access buffer size".to_string(),
            ));
        }
        if !self.verify()? {
            self.repair()?;
        }
        buffer[..N].copy_from_slice(&self.data[0]);
        buffer[N..].copy_from_slice(&self.data[1]);
        Ok(())
    }

    /// Modify the data.
    pub fn update(&mut self, data: &[u8]) -> Result<(), RadError> {
        if data.len() != N * 2 {
            return Err(RadError::Data(
                "invalid byte vector update size".to_string(),
            ));
        }
        self.data[0].copy_from_slice(&data[..N]);
        self.data[1].copy_from_slice(&data[N..]);
        ENCODER.encode(&mut self.data)?;
        let mut state = hasher()?;
        state.write(&self.data[0]);
        state.write(&self.data[1]);
        state.write(&self.data[2]);
        self.checksum = state.finish();
        Ok(())
    }
}

impl<const N: usize> Repairable for Bytes<N> {
    fn verify(&self) -> Result<bool, RadError> {
        let mut state = hasher()?;
        state.write(&self.data[0]);
        state.write(&self.data[1]);
        state.write(&self.data[2]);
        Ok(self.checksum == state.finish())
    }

    fn repair(&mut self) -> Result<(), RadError> {
        let data = self.data;
        for i in 0..data.len() {
            let mut shards: Vec<Option<_>> = data.iter().map(|x| Some(x.to_vec())).collect();
            shards[i] = None;
            ENCODER.reconstruct(&mut shards)?;
            for (xs, shard) in self.data.iter_mut().zip(shards) {
                let shard = shard.ok_or_else(|| RadError::Repair("empty shard".to_string()))?;
                xs.copy_from_slice(&shard);
            }
            if self.verify()? {
                debug!("repaired byte vector at {:#?}", self.data.as_ptr());
                return Ok(());
            }
        }
        Err(RadError::Repair("unable to repair byte vector".to_string()))
    }
}

/// Critical event.
#[derive(Serialize, Deserialize)]
pub struct Event {
    timestamp: U64,
    message: Bytes<{ MAX_MESSAGE_SIZE / 2 }>,
}

impl Event {
    /// Initialize an empty critical event.
    pub fn new() -> Result<Self, RadError> {
        Ok(Self {
            timestamp: U64::new(0)?,
            message: Bytes::new(&[0u8; MAX_MESSAGE_SIZE])?,
        })
    }

    /// Get the event.
    pub fn get(&mut self, message: &mut [u8]) -> Result<u64, RadError> {
        self.timestamp
            .get()
            .and_then(move |x| self.message.get(message).map(|_| x))
    }

    /// Update the event.
    pub fn update(&mut self, timestamp: u64, message: &[u8]) -> Result<(), RadError> {
        self.timestamp.update(timestamp)?;
        self.message.update(message)?;
        Ok(())
    }
}

impl Repairable for Event {
    fn verify(&self) -> Result<bool, RadError> {
        Ok(self.timestamp.verify()? && self.message.verify()?)
    }

    fn repair(&mut self) -> Result<(), RadError> {
        self.timestamp.repair().and_then(|_| self.message.repair())
    }
}

/// Critical module.
#[derive(Serialize, Deserialize)]
pub struct Module {
    updated: U64,
    enabled: U64,
    encoded: U64,
    verified: u64,
    #[serde(with = "BigArray")]
    signature: [u8; SIGNATURE_SIZE],
    #[serde(with = "BigArray")]
    pub(crate) code: [u8; MAX_MODULE_SIZE],
}

impl Module {
    /// Create a new module.
    pub fn new() -> Result<Self, RadError> {
        Ok(Self {
            updated: U64::new(0)?,
            enabled: U64::new(0)?,
            encoded: U64::new(0)?,
            verified: 0,
            signature: [0u8; SIGNATURE_SIZE],
            code: [0u8; MAX_MODULE_SIZE],
        })
    }

    /// Check whether the module can be updated.
    pub fn can_update(&mut self, now: u64) -> Result<bool, RadError> {
        let ts = self.updated.get()?;
        Ok(now > ts && now - ts >= MODULE_UPDATE_THRESHOLD)
    }

    /// Update the module code.
    pub fn update(&mut self, now: u64, data: &[u8], signature: &[u8]) -> Result<u64, RadError> {
        if data.len() > MAX_MODULE_SIZE {
            return Err(RadError::Protocol(
                "module exceeds maximum size".to_string(),
            ));
        }
        if signature.len() != SIGNATURE_SIZE {
            return Err(RadError::Protocol("invalid module signature".to_string()));
        }

        self.updated.update(now)?;
        self.signature.copy_from_slice(&signature);
        self.code[..data.len()].copy_from_slice(&data);
        for x in &mut self.code[data.len()..] {
            *x = 0;
        }

        hash(&self.code)
    }

    /// Check whether the module is verified.
    // noinspection ALL
    pub fn is_verified(&mut self) -> Result<bool, RadError> {
        Ok(self.verified != 0)
    }

    /// Check whether the module is encoded.
    // noinspection ALL
    pub fn is_encoded(&mut self) -> Result<bool, RadError> {
        self.encoded.get().map(|x| x != 0)
    }

    /// Set the module encoded flag.
    pub fn set_encoded(&mut self, encoded: bool) -> Result<(), RadError> {
        self.encoded.update(if encoded { 1 } else { 0 })
    }

    /// Check whether the module is enabled.
    // noinspection ALL
    pub fn is_enabled(&mut self) -> Result<bool, RadError> {
        self.enabled.get().map(|x| x != 0)
    }

    /// Set the module enable flag.
    pub fn set_enabled(&mut self, enabled: bool) -> Result<(), RadError> {
        self.enabled.update(if enabled { 1 } else { 0 })
    }

    /// Verify the module.
    pub fn verify_code(&mut self) -> Result<bool, RadError> {
        // Now, verify the signature
        let verified = RAD_PUB_KEY.verify(&self.code, &self.signature).is_ok();
        self.verified = verified.into();
        Ok(verified)
    }

    /// Execute the module.
    pub fn execute(&mut self) -> Result<Vec<u8>, RadError> {
        if self.is_verified()? && self.is_enabled()? {
            warn!("executing module");
            let mut memory = vec![0u8; 1024];
            let decode = self.is_encoded()?;
            let size = crate::vm::execute_bytes(&self.code, &mut memory, decode)? as usize;
            memory.truncate(size);
            Ok(memory)
        } else {
            Ok(vec![])
        }
    }
}

impl Repairable for Module {
    fn verify(&self) -> Result<bool, RadError> {
        Ok(self.updated.verify()? && self.enabled.verify()? && self.encoded.verify()?)
    }

    fn repair(&mut self) -> Result<(), RadError> {
        self.updated
            .verify()
            .and_then(|_| self.enabled.repair())
            .and_then(|_| self.encoded.repair())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_u64() {
        let data = 0x09a7782c013a81ed;
        let mut x = U64::new(data).expect("new u64");
        assert_eq!(x.get().expect("get u64"), data);
        assert!(x.verify().expect("verify u64"));
        for i in 0..4 {
            x.data[0][i] |= 0x80;
            assert_eq!(x.get().expect("get u64"), data);
        }
    }

    #[test]
    fn repair_bytes() {
        let data = b"\x09\xa7\x78\x2c\x01\x3a\x81\xed";
        let mut x = Bytes::<4>::new(&data[..]).expect("new bytes");
        let mut buffer = vec![0u8; data.len()];
        x.get(&mut buffer).expect("get bytes");
        assert_eq!(buffer, data);
        assert!(x.verify().expect("verify bytes"));
        for i in 0..x.data[0].len() {
            x.data[0][i] |= 0x80;
            x.get(&mut buffer).expect("get bytes");
            assert_eq!(buffer, data);
        }
    }

    #[test]
    fn serialize_bytes() {
        let data = b"\x09\xa7\x78\x2c\x01\x3a\x81\xed";
        let x = Bytes::<4>::new(&data[..]).expect("new bytes");
        let buffer = bincode::serialize(&x).expect("serialize");
        let y: Bytes<4> = bincode::deserialize(&buffer).expect("deserialize");
        assert_eq!(x, y);
    }

    #[test]
    fn shards() {
        let mut data = [[1u8, 2, 3, 4], [5, 6, 7, 8], [0, 0, 0, 0]];
        ENCODER.encode(&mut data).expect("encode");
        data[0][0] = 2;
        let mut shards: Vec<Option<Vec<_>>> = data.iter().map(|x| Some(x.to_vec())).collect();
        shards[0] = None;
        ENCODER.reconstruct(&mut shards).expect("reconstruct");
        data[0][0] = shards[0].as_ref().unwrap()[0];
        assert!(ENCODER.verify(&data).expect("verify"));
    }
}
