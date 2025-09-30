//! RandomX Proof of Work implementation for Grin/Lurker.

use crate::core::block::BlockHeader;
use crate::core::hash::Hash;
use crate::core::pow::{PowError, ProofOfWork};
use crate::core::ser::{ProtocolVersion, Readable, Reader, SerError, Writeable, Writer};
use crate::core::Difficulty;
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
use std::io;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomXProofOfWork {
	pub nonce: u64,
}

impl ProofOfWork for RandomXProofOfWork {
	fn size(&self) -> usize {
		8 // Size of u64 nonce
	}

	fn verify(&self, header: &BlockHeader) -> Result<(), PowError> {
		// Use pre-nonce hash as key for RandomX cache
		let pre_hash = header
			.hash_without_nonce()
			.map_err(|e| PowError::Other(format!("Hash without nonce: {}", e)))?;
		let flags = RandomXFlag::DEFAULT | RandomXFlag::FULL_MEM;
		let key = pre_hash.as_bytes();

		let cache = RandomXCache::new(flags, key)
			.map_err(|e| PowError::Other(format!("RandomX cache init: {}", e)))?;
		let vm = RandomXVM::new(flags, Some(&cache))
			.map_err(|e| PowError::Other(format!("RandomX VM init: {}", e)))?;

		// Serialize full header (including nonce) as input to VM
		let mut header_bytes = vec![];
		header
			.write(&mut Writer::new(&mut header_bytes, ProtocolVersion::V2))
			.map_err(|e| PowError::Other(format!("Header serialization: {}", e)))?;
		let input = &header_bytes[..];

		// Compute RandomX hash output
		let output = vm
			.calculate(input)
			.map_err(|e| PowError::Other(format!("RandomX calculate: {}", e)))?;
		let pow_hash = Hash::from_vec(&output.to_vec());

		// Verify against header difficulty (using Grin's difficulty_from_hash if needed)
		let computed_difficulty = Difficulty::from_hash(&pow_hash);
		if computed_difficulty >= header.difficulty {
			Ok(())
		} else {
			Err(PowError::Other(
				"Insufficient proof-of-work difficulty".into(),
			))
		}
	}
}

impl Writeable for RandomXProofOfWork {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.nonce.write(writer)
	}
}

impl Readable for RandomXProofOfWork {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, SerError> {
		let nonce = u64::read(reader)?;
		Ok(Self { nonce })
	}
}
