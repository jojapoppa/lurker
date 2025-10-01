// core/src/mining.rs
use crate::consensus::Difficulty;
use crate::core::block::BlockHeader;
use crate::core::hash::Hash;
use crate::pow::PowError;
use crate::ser::{ProtocolVersion, Writer};
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
use std::time::{Duration, Instant};

/// Mines a block header by iterating nonces until the hash meets the difficulty target.
/// Returns the valid nonce if found within timeout (60s), or None.
pub fn mine_header(header: &mut BlockHeader, difficulty: Difficulty) -> Option<u64> {
	let flags = RandomXFlag::DEFAULT | RandomXFlag::FULL_MEM;
	let pre_hash = header.hash_without_nonce().ok_or(PowError::HashFail)?;
	let key = pre_hash.as_bytes();

	let cache = RandomXCache::new(flags, key).map_err(|e| PowError::CacheInit(e.to_string()))?;
	let vm = RandomXVM::new(flags, Some(&cache)).map_err(|_| PowError::VMCreate)?;

	let mut nonce: u64 = 0;
	let start = Instant::now();
	let timeout = Duration::from_secs(60);

	loop {
		if start.elapsed() > timeout {
			return None; // Timeout to prevent infinite loop
		}

		header.nonce = nonce;

		let mut header_bytes = Vec::new();
		let mut writer = Writer::new(&mut header_bytes, ProtocolVersion::default());
		header.write(&mut writer).map_err(|_| PowError::HashFail)?;

		let input = &header_bytes[..];
		let output = vm.calculate(input);
		let hash_arr: [u8; 32] = output.try_into().map_err(|_| PowError::HashFail)?;
		let pow_hash = Hash::from_vec(&hash_arr);
		let hash_diff = Difficulty::from_hash(hash_arr);

		if hash_diff >= difficulty {
			header.pow = RandomXProofOfWork::new(nonce); // Assume constructor
			return Some(nonce);
		}

		nonce = nonce.wrapping_add(1);
	}
}
