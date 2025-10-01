// Copyright 2021 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The proof of work needs to strike a balance between fast header
//! verification to avoid DoS attacks and difficulty for block verifiers to
//! build new blocks. In addition, mining new blocks should also be as
//! difficult on high end custom-made hardware (ASICs) as on commodity hardware
//! or smartphones. For this reason we use RandomX (as it is also Quantum Resistant as well)
//!
//! Note that this miner implementation is here mostly for tests and
//! reference. It's not optimized for speed.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

use crate::consensus::Difficulty;
use crate::core::block::BlockHeader;
pub use crate::core::block::Error;
use crate::core::Block;
use crate::genesis;
use crate::global;
use crate::ser::{ProtocolVersion, Readable, Reader, Writeable, Writer};
use chrono::prelude::{DateTime, Utc};
use randomx_rs::{RandomXCache, RandomXError, RandomXFlag, RandomXVM};
use serde::{Deserialize, Serialize};

pub mod error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowError {
	CacheInit(String),
	VMCreate,
	HashFail,
	InvalidNonce,
	UnsupportedVersion,
}

impl std::fmt::Display for PowError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			PowError::CacheInit(s) => write!(f, "Cache initialization error: {}", s),
			PowError::VMCreate => write!(f, "VM creation error"),
			PowError::HashFail => write!(f, "Hash computation failed"),
			PowError::InvalidNonce => write!(f, "Invalid nonce"),
			PowError::UnsupportedVersion => write!(f, "Unsupported header version for RandomX"),
		}
	}
}

pub use error::PowError;

/// RandomX-specific PoW type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowType {
	#[serde(rename = "RandomX")]
	RandomX,
}

/// Trait for proof of work implementations
pub trait ProofOfWork: Readable + Writeable {
	fn size(&self) -> usize;
	fn verify(&self, header: &BlockHeader) -> Result<(), PowError>;
}

/// Returns the PoW type for a given header
pub fn get_pow_type(_header: &BlockHeader) -> Result<PowType, PowError> {
	Ok(PowType::RandomX)
}

/// Creates a new RandomX cache from the given seed (header pre-PoW bytes).
/// Uses FLAG_DEFAULT for standard CPU-optimized setup (JIT + large pages if available).
pub fn new_randomx_cache(seed: &[u8]) -> Result<RandomXCache, PowError> {
	match RandomXCache::new(RandomXFlag::FLAG_DEFAULT, seed) {
		Ok(cache) => Ok(cache),
		Err(e) => Err(PowError::CacheInit(format!("RandomXError: {:?}", e))),
	}
}

/// RandomX-specific proof of work
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomXProofOfWork {
	/// The nonce
	pub nonce: u64,
	/// Total difficulty
	pub total_difficulty: Difficulty,
	/// Internal cache (for reuse in mining/verif; not serialized)
	#[serde(skip)]
	cache: Option<RandomXCache>,
}

impl RandomXProofOfWork {
	/// Creates a new RandomX PoW instance from cache (for mining/verif).
	pub fn new(cache: RandomXCache) -> Self {
		Self {
			cache: Some(cache),
			nonce: 0,
			total_difficulty: Difficulty::zero(),
		}
	}

	/// Verifies the PoW by computing hash(seed + nonce) and checking against difficulty target.
	pub fn verify_internal(&self, seed: &[u8]) -> Result<(), PowError> {
		let cache = self
			.cache
			.as_ref()
			.ok_or(PowError::CacheInit("No cache".to_string()))?;
		let vm = match RandomXVM::new(RandomXFlag::FLAG_DEFAULT, Some(cache.clone()), None) {
			Ok(vm) => vm,
			Err(_) => return Err(PowError::VMCreate),
		};
		let input = [seed, &self.nonce.to_le_bytes()].concat();
		let hash_bytes = match vm.calculate_hash(&input) {
			Ok(bytes) => bytes,
			Err(_) => return Err(PowError::HashFail),
		};
		drop(vm); // Free VM

		// Check hash_bytes length
		if hash_bytes.len() != 32 {
			return Err(PowError::HashFail);
		}

		// Copy Vec<u8> into [u8; 32]
		let mut hash_arr = [0u8; 32];
		hash_arr.copy_from_slice(&hash_bytes[..32]);
		let hash_diff = Difficulty::from_hash(hash_arr);

		if hash_diff >= self.total_difficulty {
			Ok(())
		} else {
			Err(PowError::InvalidNonce)
		}
	}
}

impl Readable for RandomXProofOfWork {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, crate::ser::Error> {
		let nonce = reader.read_u64()?;
		let total_difficulty = Difficulty::read(reader)?;
		// Cache not serialized; recreated during verify
		Ok(Self {
			nonce,
			total_difficulty,
			cache: None,
		})
	}
}

impl Writeable for RandomXProofOfWork {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), crate::ser::Error> {
		writer.write_u64(self.nonce)?;
		self.total_difficulty.write(writer)?;
		Ok(())
	}
}

impl ProofOfWork for RandomXProofOfWork {
	fn size(&self) -> usize {
		8 + 8 // nonce (u64) + difficulty (u64)
	}

	fn verify(&self, header: &BlockHeader) -> Result<(), PowError> {
		let seed = &header.pre_pow();
		self.verify_internal(seed)
	}
}

/// Validates the proof of work of a given header (RandomX version).
pub fn verify_size(bh: &BlockHeader) -> Result<(), crate::core::block::Error> {
	match bh.pow.verify(bh) {
		Ok(()) => Ok(()),
		Err(e) => Err(crate::core::block::Error::Pow(e)),
	}
}

/// Mines a genesis block using the internal miner
pub fn mine_genesis_block() -> Result<Block, crate::core::block::Error> {
	let mut gen = genesis::genesis_dev();
	let genesis_difficulty = Difficulty::min_dma();
	let seed = gen.header.pre_pow();
	let pow = match global::create_pow_context(gen.header.height, &seed) {
		Ok(pow) => pow,
		Err(e) => return Err(crate::core::block::Error::Pow(e)),
	};
	gen.header.pow = pow;
	pow_size(&mut gen.header, genesis_difficulty)?;
	Ok(gen)
}

/// Runs a proof of work computation over the provided block header until the required difficulty target is reached.
/// May take a while for a low target...
pub fn pow_size(bh: &mut BlockHeader, diff: Difficulty) -> Result<(), crate::core::block::Error> {
	let mut seed = bh.pre_pow();
	let mut nonce = bh.pow.nonce;
	let start_nonce = nonce;
	let mut iter = 0;
	const MAX_ITER: u64 = 1_000_000; // Timeout for tests

	let mut pow = match global::create_pow_context(bh.height, &seed) {
		Ok(pow) => pow,
		Err(e) => return Err(crate::core::block::Error::Pow(e)),
	};
	let mut vm = match RandomXVM::new(
		RandomXFlag::FLAG_DEFAULT,
		Some(pow.cache.clone().unwrap()),
		None,
	) {
		Ok(vm) => vm,
		Err(_) => return Err(crate::core::block::Error::Pow(PowError::VMCreate)),
	};

	loop {
		if iter > MAX_ITER {
			return Err(crate::core::block::Error::Pow(PowError::InvalidNonce)); // Timeout
		}

		// Compute hash for current nonce
		let input = [seed.as_slice(), &nonce.to_le_bytes()].concat();
		let hash_bytes = match vm.calculate_hash(&input) {
			Ok(bytes) => bytes,
			Err(_) => return Err(crate::core::block::Error::Pow(PowError::HashFail)),
		};

		// Check hash_bytes length
		if hash_bytes.len() != 32 {
			return Err(crate::core::block::Error::Pow(PowError::HashFail));
		}

		// Copy Vec<u8> into [u8; 32]
		let mut hash_arr = [0u8; 32];
		hash_arr.copy_from_slice(&hash_bytes[..32]);
		let hash_diff = Difficulty::from_hash(hash_arr);

		// If valid, set PoW and break
		if hash_diff >= diff {
			bh.pow.nonce = nonce;
			bh.pow.total_difficulty = hash_diff;
			bh.pow.cache = pow.cache.take(); // Store cache
			return Ok(());
		}

		// Increment nonce
		nonce = nonce.overflowing_add(1).0;

		// If nonce wraps, update timestamp (changes seed)
		if nonce == start_nonce {
			bh.timestamp = Utc::now();
			seed = bh.pre_pow();
			// Recreate PoW context for new seed
			pow = match global::create_pow_context(bh.height, &seed) {
				Ok(pow) => pow,
				Err(e) => return Err(crate::core::block::Error::Pow(e)),
			};
			// Recreate VM with new cache
			vm = match RandomXVM::new(
				RandomXFlag::FLAG_DEFAULT,
				Some(pow.cache.clone().unwrap()),
				None,
			) {
				Ok(vm) => vm,
				Err(_) => return Err(crate::core::block::Error::Pow(PowError::VMCreate)),
			};
		}

		iter += 1;
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::global::ChainTypes;

	#[test]
	fn test_new_randomx_cache() {
		let seed = b"test_seed_32_bytes!!"; // RandomX requires >=32 bytes
		let cache = new_randomx_cache(seed).unwrap();
		// Basic sanity: cache created successfully
		drop(cache);
	}

	#[test]
	fn genesis_pow() {
		global::set_local_chain_type(ChainTypes::UserTesting);

		let mut b = genesis::genesis_dev();
		b.header.pow.nonce = 0; // Start from 0

		pow_size(&mut b.header, Difficulty::min_dma()).unwrap();

		assert_ne!(b.header.pow.nonce, 0);
		assert!(b.header.pow.total_difficulty >= Difficulty::min_dma());
		assert!(verify_size(&b.header).is_ok());
	}
}
