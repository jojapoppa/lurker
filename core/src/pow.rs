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

use crate::core::block::BlockHeader;
use crate::core::ser::{ProtocolVersion, Readable, Reader, Writeable, Writer};
use crate::genesis;
use crate::global;
use chrono::prelude::{DateTime, Utc};
use randomx_rs::{RandomXCache, RandomXError, RandomXFlag, RandomXVM};
use serde::{Deserialize, Serialize};

pub mod error;
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
/// Uses DEFAULT flags for standard CPU-optimized setup (JIT + large pages if available).
pub fn new_randomx_cache(seed: &[u8]) -> Result<RandomXCache, PowError> {
	RandomXCache::new(RandomXFlag::DEFAULT, seed)
		.map_err(|e: RandomXError| PowError::CacheInit(format!("RandomXError: {:?}", e)))
}

/// Temporary Difficulty stub for PoW (move to consensus.rs for full impl)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Difficulty(pub u64);

impl Difficulty {
	pub const LEN: usize = 8;

	/// Zero difficulty
	pub fn zero() -> Difficulty {
		Difficulty(0)
	}

	/// Minimum DMA difficulty
	pub fn min_dma() -> Difficulty {
		Difficulty(global::MIN_DMA_DIFFICULTY)
	}

	/// Minimum WTEMA difficulty (for RandomX)
	pub fn min_wtema() -> Difficulty {
		Difficulty(global::C32_GRAPH_WEIGHT) // Stubbed value
	}

	/// Convert to numeric value
	pub fn to_num(&self) -> u64 {
		self.0
	}

	/// Convert from numeric value
	pub fn from_num(d: u64) -> Difficulty {
		Difficulty(d)
	}

	/// For RandomX: Convert hash to difficulty (count leading zero bytes as bits of difficulty)
	pub fn from_hash(hash: [u8; 32]) -> Difficulty {
		let mut leading_zeros = 0u64;
		for &byte in &hash {
			if byte == 0 {
				leading_zeros += 8;
			} else {
				leading_zeros += (byte.leading_zeros() as u64);
				break;
			}
		}
		Difficulty(1u64 << leading_zeros.min(64)) // Cap at u64::MAX
	}
}

impl Readable for Difficulty {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, crate::ser::Error> {
		let num = reader.read_u64()?;
		Ok(Difficulty::from_num(num))
	}
}

impl Writeable for Difficulty {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), crate::ser::Error> {
		writer.write_u64(self.0)
	}
}

/// RandomX-specific proof of work
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
		let vm = RandomXVM::new(cache, RandomXFlag::DEFAULT).map_err(|_| PowError::VMCreate)?;
		let input = [seed, &self.nonce.to_le_bytes()].concat();
		let hash_bytes = vm.calculate(&input);
		drop(vm); // Free VM

		let hash_arr: [u8; 32] = hash_bytes.try_into().map_err(|_| PowError::HashFail)?;
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
		8 + Difficulty::LEN // nonce + difficulty
	}

	fn verify(&self, header: &BlockHeader) -> Result<(), PowError> {
		let seed = &header.pre_pow();
		self.verify_internal(seed)
	}
}

/// Validates the proof of work of a given header (RandomX version).
pub fn verify_size(bh: &BlockHeader) -> Result<(), PowError> {
	bh.pow.verify(bh)
}

/// Mines a genesis block using the internal miner
pub fn mine_genesis_block() -> Result<Block, PowError> {
	let mut gen = genesis::genesis_dev();

	// total_difficulty on the genesis header *is* the difficulty of that block
	let genesis_difficulty = Difficulty::min_dma(); // Or gen.header.pow.total_difficulty if set

	let seed = gen.header.pre_pow();
	let cache = new_randomx_cache(&seed)?;

	// Set initial PoW
	gen.header.pow = RandomXProofOfWork::new(cache);

	pow_size(&mut gen.header, genesis_difficulty)?;
	Ok(gen)
}

/// Runs a proof of work computation over the provided block header until the required difficulty target is reached.
/// May take a while for a low target...
pub fn pow_size(bh: &mut BlockHeader, diff: Difficulty) -> Result<(), PowError> {
	let mut seed = bh.pre_pow();
	let mut nonce = bh.pow.nonce;
	let mut start_nonce = nonce;

	let cache = new_randomx_cache(&seed)?;

	loop {
		// Create VM and compute hash for current nonce
		let vm = RandomXVM::new(&cache, RandomXFlag::DEFAULT).map_err(|_| PowError::VMCreate)?;
		let input = [seed.as_slice(), &nonce.to_le_bytes()].concat();
		let hash_bytes = vm.calculate(&input);
		drop(vm);

		let hash_arr: [u8; 32] = hash_bytes.try_into().map_err(|_| PowError::HashFail)?;
		let hash_diff = Difficulty::from_hash(hash_arr);

		// If valid, set PoW and break
		if hash_diff >= diff {
			bh.pow.nonce = nonce;
			bh.pow.total_difficulty = hash_diff;
			bh.pow.cache = Some(cache); // Reuse if needed
			return Ok(());
		}

		// Increment nonce
		let (new_nonce, overflowed) = nonce.overflowing_add(1);
		nonce = new_nonce;

		// If nonce wraps, update timestamp (changes seed)
		if overflowed {
			bh.timestamp = Utc::now();
			seed = bh.pre_pow();
			// Recreate cache for new seed
			let new_cache = new_randomx_cache(&seed)?;
			bh.pow.cache = Some(new_cache);
			drop(cache);
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::genesis;
	use crate::global::{set_local_chain_type, ChainTypes};

	/// Test RandomX cache creation
	#[test]
	fn test_new_randomx_cache() {
		let seed = b"test_seed_32_bytes!!"; // RandomX requires >=32 bytes
		let cache = new_randomx_cache(seed).unwrap();
		// Basic sanity: cache created successfully
		drop(cache);
	}

	/// Test genesis PoW mining
	#[test]
	fn genesis_pow() {
		set_local_chain_type(ChainTypes::UserTesting);

		let mut b = genesis::genesis_dev();
		b.header.pow.nonce = 0; // Start from 0

		pow_size(&mut b.header, Difficulty::min_dma()).unwrap();

		assert_ne!(b.header.pow.nonce, 0);
		assert!(b.header.pow.total_difficulty >= Difficulty::min_dma());
		assert!(verify_size(&b.header).is_ok());
	}
}
