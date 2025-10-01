// Copyright 2021 The Grin Developers
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

//! All the rules required for a cryptocurrency to have reach consensus across
//! the whole network are complex and hard to completely isolate. Some can be
//! simple parameters (like block reward), others complex algorithms (like
//! Merkle sum trees or reorg rules). However, as long as they're simple
//! enough, consensus-relevant constants and short functions should be kept
//! here.

use crate::core::block::{Block, HeaderVersion};
use crate::core::hash::Hash;
use crate::global;
use crate::pow::{PowError, RandomXProofOfWork};
use crate::ser::{Readable, Reader, Writeable, Writer};
use serde::{Deserialize, Serialize};
use std::cmp::{max, min};

/// Errors specific to consensus rules
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Difficulty is invalid
	#[error("Invalid difficulty")]
	InvalidDifficulty,
	/// Header version is invalid
	#[error("Invalid header version")]
	InvalidHeaderVersion,
	/// PoW verification failed
	#[error("PoW verification failed: {0}")]
	PowVerification(PowError),
	// Add more as needed
}

impl From<PowError> for Error {
	fn from(e: PowError) -> Self {
		Error::PowVerification(e)
	}
}

/// Difficulty type (adapted for RandomX: u64-based, with hash-to-difficulty conversion)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Difficulty(pub u64);

impl Difficulty {
	/// Zero difficulty
	pub fn zero() -> Difficulty {
		Difficulty(0)
	}

	/// Minimum DMA difficulty
	pub fn min_dma() -> Difficulty {
		Difficulty(MIN_DMA_DIFFICULTY)
	}

	/// Minimum WTEMA difficulty (for RandomX)
	pub fn min_wtema() -> Difficulty {
		Difficulty(C32_GRAPH_WEIGHT) // Stubbed value for RandomX
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

impl std::fmt::Display for Difficulty {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

/// A grin is divisible to 10^9, following the SI prefixes
pub const GRIN_BASE: u64 = 1_000_000_000;
/// Milligrin, a thousand of a grin
pub const MILLI_GRIN: u64 = GRIN_BASE / 1_000;
/// Microgrin, a thousand of a milligrin
pub const MICRO_GRIN: u64 = MILLI_GRIN / 1_000;
/// Nanogrin, smallest unit, takes a billion to make a grin
pub const NANO_GRIN: u64 = 1;

/// Block interval, in seconds, the network will tune its next_target for. Note
/// that we may reduce this value in the future as we get more data on mining
/// with RandomX, networks improve and block propagation is optimized
/// (adjusting the reward accordingly).
pub const BLOCK_TIME_SEC: u64 = 60;

/// The block subsidy amount, one grin per second on average
pub const REWARD: u64 = BLOCK_TIME_SEC * GRIN_BASE;

/// Actual block reward for a given total fee amount
pub fn reward(fee: u64) -> u64 {
	REWARD.saturating_add(fee)
}

/// an hour in seconds
pub const HOUR_SEC: u64 = 60 * 60;

/// Nominal height for standard time intervals, hour is 60 blocks
pub const HOUR_HEIGHT: u64 = HOUR_SEC / BLOCK_TIME_SEC;
/// A day is 1440 blocks
pub const DAY_HEIGHT: u64 = 24 * HOUR_HEIGHT;
/// A week is 10_080 blocks
pub const WEEK_HEIGHT: u64 = 7 * DAY_HEIGHT;
/// A year is 524_160 blocks
pub const YEAR_HEIGHT: u64 = 52 * WEEK_HEIGHT;

/// Number of blocks before a coinbase matures and can be spent
pub const COINBASE_MATURITY: u64 = DAY_HEIGHT;

/// Target ratio of secondary proof of work to primary proof of work,
/// as a function of block height (time). Starts at 90% losing a percent
/// approximately every week. Represented as an integer between 0 and 100.
/// (Stubbed for RandomX: No secondary PoW)
pub fn secondary_pow_ratio(_height: u64) -> u64 {
	0 // RandomX has no secondary PoW
}

/// (Legacy stub for RandomX: No proofs/edge_bits)
pub const PROOFSIZE: usize = 0;

/// Default RandomX difficulty scaling (stub; RandomX uses hash-based diff)
pub const DEFAULT_MIN_EDGE_BITS: u8 = 0;

/// (Legacy stub)
pub const SECOND_POW_EDGE_BITS: u8 = 0;

/// Original reference edge_bits to compute difficulty factors for higher
/// graphs, changing this would hard fork (stubbed for RandomX)
pub const BASE_EDGE_BITS: u8 = 0;

/// Default number of blocks in the past when cross-block cut-through will start
/// happening. Needs to be long enough to not overlap with a long reorg.
/// Rational
/// behind the value is the longest bitcoin fork was about 30 blocks, so 5h. We
/// add an order of magnitude to be safe and round to 7x24h of blocks to make it
/// easier to reason about.
pub const CUT_THROUGH_HORIZON: u32 = WEEK_HEIGHT as u32;

/// Default number of blocks in the past to determine the height where we request
/// a txhashset (and full blocks from). Needs to be long enough to not overlap with
/// a long reorg.
/// Rational behind the value is the longest bitcoin fork was about 30 blocks, so 5h.
/// We add an order of magnitude to be safe and round to 2x24h of blocks to make it
/// easier to reason about.
pub const STATE_SYNC_THRESHOLD: u32 = 2 * DAY_HEIGHT as u32;

/// Weight of an input when counted against the max block weight capacity
pub const INPUT_WEIGHT: u64 = 1;

/// Weight of an output when counted against the max block weight capacity
pub const OUTPUT_WEIGHT: u64 = 21;

/// Weight of a kernel when counted against the max block weight capacity
pub const KERNEL_WEIGHT: u64 = 3;

/// Total maximum block weight. At current sizes, this means a maximum
/// theoretical size of:
/// * `(674 + 33 + 1) * (40_000 / 21) = 1_348_571` for a block with only outputs
/// * `(1 + 8 + 8 + 33 + 64) * (40_000 / 3) = 1_520_000` for a block with only kernels
/// * `(1 + 33) * 40_000 = 1_360_000` for a block with only inputs
///
/// Regardless of the relative numbers of inputs/outputs/kernels in a block the maximum
/// block size is around 1.5MB
/// For a block full of "average" txs (2 inputs, 2 outputs, 1 kernel) we have -
/// `(1 * 2) + (21 * 2) + (3 * 1) = 47` (weight per tx)
/// `40_000 / 47 = 851` (txs per block)
///
pub const MAX_BLOCK_WEIGHT: u64 = 40_000;

/// Fork every 6 months (large interval for new coin; adjust for future upgrades).
pub const HARD_FORK_INTERVAL: u64 = 10 * YEAR_HEIGHT; // Effectively no forks until planned

/// Fork every 3 blocks (for testing; new coin can set high to disable)
pub const TESTING_HARD_FORK_INTERVAL: u64 = YEAR_HEIGHT;

/// Compute possible block version at a given height, implements
/// interval scheduled hard forks.
pub fn header_version(height: u64) -> HeaderVersion {
	let hf_interval = (1 + height / HARD_FORK_INTERVAL) as u16;
	match global::get_chain_type() {
		global::ChainTypes::Mainnet | global::ChainTypes::Testnet => HeaderVersion(1), // Start at v1 for new coin
		global::ChainTypes::AutomatedTesting | global::ChainTypes::UserTesting => {
			let testing_hf_interval = (1 + height / TESTING_HARD_FORK_INTERVAL) as u16;
			HeaderVersion(min(5, testing_hf_interval)) // Keep for tests
		}
	}
}

/// Check whether the block version is valid at a given height, implements
/// interval scheduled hard forks.
pub fn valid_header_version(height: u64, version: HeaderVersion) -> bool {
	version == header_version(height)
}

/// Number of blocks used to calculate difficulty adjustment by Damped Moving Average
pub const DMA_WINDOW: u64 = HOUR_HEIGHT;

/// Difficulty adjustment half life (actually, 60s * number of 0s-blocks to raise diff by factor e) is 4 hours
pub const WTEMA_HALF_LIFE: u64 = 4 * HOUR_SEC;

/// Average time span of the DMA difficulty adjustment window
pub const BLOCK_TIME_WINDOW: u64 = DMA_WINDOW * BLOCK_TIME_SEC;

/// Clamp factor to use for DMA difficulty adjustment
/// Limit value to within this factor of goal
pub const CLAMP_FACTOR: u64 = 2;

/// Dampening factor to use for DMA difficulty adjustment
pub const DMA_DAMP_FACTOR: u64 = 3;

/// Dampening factor to use for AR scale calculation.
pub const AR_SCALE_DAMP_FACTOR: u64 = 13;

/// Compute weight of a graph as number of siphash bits defining the graph
/// (Stubbed for RandomX: Fixed weight, no graphs)
pub fn graph_weight(_height: u64, _edge_bits: u8) -> u64 {
	1 // Unit weight for RandomX hash difficulty
}

/// minimum solution difficulty after HardFork4 when PoW becomes primary only Cuckatoo32+
/// (Stubbed for RandomX)
pub const C32_GRAPH_WEIGHT: u64 = 1;

/// Minimum difficulty, enforced in Damped Moving Average diff retargetting
/// avoids getting stuck when trying to increase difficulty subject to dampening
pub const MIN_DMA_DIFFICULTY: u64 = DMA_DAMP_FACTOR;

/// Minimum scaling factor for AR pow, enforced in diff retargetting
/// avoids getting stuck when trying to increase ar_scale subject to dampening
pub const MIN_AR_SCALE: u64 = AR_SCALE_DAMP_FACTOR;

/// unit difficulty, equal to graph_weight(SECOND_POW_EDGE_BITS)
/// (Stubbed for RandomX)
pub const UNIT_DIFFICULTY: u64 = 1;

/// The initial difficulty at launch. This should be over-estimated
/// and difficulty should come down at launch rather than up
/// Currently grossly over-estimated at 10% of current
/// ethereum GPUs (assuming 1GPU can solve a block at diff 1 in one block interval)
pub const INITIAL_DIFFICULTY: u64 = 1_000_000 * UNIT_DIFFICULTY;

/// Minimal header information required for the Difficulty calculation to
/// take place. Used to iterate through a number of blocks. Note that an instance
/// of this is unable to calculate its own hash, due to an optimization that prevents
/// the header's PoW proof nonces from being deserialized on read
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderDifficultyInfo {
	/// Hash of this block
	pub hash: Option<Hash>,
	/// Timestamp of the header, 1 when not used (returned info)
	pub timestamp: u64,
	/// Network difficulty or next difficulty to use
	pub difficulty: Difficulty,
	/// Network secondary PoW factor or factor to use
	pub secondary_scaling: u32,
	/// Whether the header is a secondary proof of work
	pub is_secondary: bool,
}

impl HeaderDifficultyInfo {
	/// Default constructor
	pub fn new(
		hash: Option<Hash>,
		timestamp: u64,
		difficulty: Difficulty,
		secondary_scaling: u32,
		is_secondary: bool,
	) -> HeaderDifficultyInfo {
		HeaderDifficultyInfo {
			hash,
			timestamp,
			difficulty,
			secondary_scaling,
			is_secondary,
		}
	}

	/// Constructor from a timestamp and difficulty, setting a default secondary
	/// PoW factor
	pub fn from_ts_diff(timestamp: u64, difficulty: Difficulty) -> HeaderDifficultyInfo {
		HeaderDifficultyInfo {
			hash: None,
			timestamp,
			difficulty,
			secondary_scaling: global::initial_graph_weight(),
			is_secondary: false, // RandomX: No secondary
		}
	}

	/// Constructor from a difficulty and secondary factor, setting a default
	/// timestamp
	pub fn from_diff_scaling(
		difficulty: Difficulty,
		secondary_scaling: u32,
	) -> HeaderDifficultyInfo {
		HeaderDifficultyInfo {
			hash: None,
			timestamp: 1,
			difficulty,
			secondary_scaling,
			is_secondary: false, // RandomX: No secondary
		}
	}
}

/// Move value linearly toward a goal
pub fn damp(actual: u64, goal: u64, damp_factor: u64) -> u64 {
	(actual + (damp_factor - 1) * goal) / damp_factor
}

/// limit value to be within some factor from a goal
pub fn clamp(actual: u64, goal: u64, clamp_factor: u64) -> u64 {
	max(goal / clamp_factor, min(actual, goal * clamp_factor))
}

/// Computes the proof-of-work difficulty that the next block should comply with.
/// Takes an iterator over past block headers information, from latest
/// (highest height) to oldest (lowest height).
/// Uses either the old dma DAA or, starting from HF4, the new wtema DAA
pub fn next_difficulty<T>(height: u64, cursor: T) -> HeaderDifficultyInfo
where
	T: IntoIterator<Item = HeaderDifficultyInfo>,
{
	if header_version(height) < HeaderVersion(5) {
		next_dma_difficulty(height, cursor)
	} else {
		next_wtema_difficulty(height, cursor)
	}
}

/// Difficulty calculation based on a Damped Moving Average
/// of difficulty over a window of DMA_WINDOW blocks.
/// The corresponding timespan is calculated
/// by using the difference between the timestamps at the beginning
/// and the end of the window, with a damping toward the target block time.
pub fn next_dma_difficulty<T>(height: u64, cursor: T) -> HeaderDifficultyInfo
where
	T: IntoIterator<Item = HeaderDifficultyInfo>,
{
	// Create vector of difficulty data running from earliest
	// to latest, and pad with simulated pre-genesis data to allow earlier
	// adjustment if there isn't enough window data length will be
	// DMA_WINDOW + 1 (for initial block time bound)
	let diff_data = global::difficulty_data_to_vector(cursor);

	// First, get the ratio of secondary PoW vs primary, skipping initial header
	let sec_pow_scaling = secondary_pow_scaling(height, &diff_data[1..]);

	// Get the timestamp delta across the window
	let ts_delta: u64 = diff_data[DMA_WINDOW as usize].timestamp - diff_data[0].timestamp;

	// Get the difficulty sum of the last DMA_WINDOW elements
	let diff_sum: u64 = diff_data
		.iter()
		.skip(1)
		.map(|dd| dd.difficulty.to_num())
		.sum();

	// adjust time delta toward goal subject to dampening and clamping
	let adj_ts = clamp(
		damp(ts_delta, BLOCK_TIME_WINDOW, DMA_DAMP_FACTOR),
		BLOCK_TIME_WINDOW,
		CLAMP_FACTOR,
	);
	// minimum difficulty avoids getting stuck due to dampening
	let difficulty = max(MIN_DMA_DIFFICULTY, diff_sum * BLOCK_TIME_SEC / adj_ts);

	HeaderDifficultyInfo::from_diff_scaling(Difficulty::from_num(difficulty), sec_pow_scaling)
}

/// Difficulty calculation based on a Weighted Target Exponential Moving Average
/// of difficulty, using the ratio of the last block time over the target block time.
pub fn next_wtema_difficulty<T>(_height: u64, cursor: T) -> HeaderDifficultyInfo
where
	T: IntoIterator<Item = HeaderDifficultyInfo>,
{
	let mut last_headers = cursor.into_iter();

	// last two headers
	let last_header = last_headers.next().unwrap();
	let prev_header = last_headers.next().unwrap();

	let last_block_time: u64 = last_header.timestamp - prev_header.timestamp;

	let last_diff = last_header.difficulty.to_num();

	// wtema difficulty update
	let next_diff =
		last_diff * WTEMA_HALF_LIFE / (WTEMA_HALF_LIFE - BLOCK_TIME_SEC + last_block_time);

	// mainnet minimum difficulty at graph_weight(32) ensures difficulty increase on 59s block
	// since 16384 * WTEMA_HALF_LIFE / (WTEMA_HALF_LIFE - 1) > 16384
	let difficulty = max(Difficulty::min_wtema(), Difficulty::from_num(next_diff));

	HeaderDifficultyInfo::from_diff_scaling(difficulty, 0) // no more secondary PoW
}

/// Count, in units of 1/100 (a percent), the number of "secondary" (AR) blocks in the provided window of blocks.
pub fn ar_count(_height: u64, diff_data: &[HeaderDifficultyInfo]) -> u64 {
	100 * diff_data.iter().filter(|n| n.is_secondary).count() as u64
}

/// The secondary proof-of-work factor is calculated along the same lines as in next_dma_difficulty,
/// as an adjustment on the deviation against the ideal value.
/// Factor by which the secondary proof of work difficulty will be adjusted
pub fn secondary_pow_scaling(height: u64, diff_data: &[HeaderDifficultyInfo]) -> u32 {
	// Get the scaling factor sum of the last DMA_WINDOW elements
	let scale_sum: u64 = diff_data.iter().map(|dd| dd.secondary_scaling as u64).sum();

	// compute ideal 2nd_pow_fraction in pct and across window
	let target_pct = secondary_pow_ratio(height);
	let target_count = DMA_WINDOW * target_pct;

	// Get the secondary count across the window, adjusting count toward goal
	// subject to dampening and clamping.
	let adj_count = clamp(
		damp(
			ar_count(height, diff_data),
			target_count,
			AR_SCALE_DAMP_FACTOR,
		),
		target_count,
		CLAMP_FACTOR,
	);
	let scale = scale_sum * target_pct / max(1, adj_count);

	// minimum AR scale avoids getting stuck due to dampening
	max(MIN_AR_SCALE, scale) as u32
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::global::ChainTypes;

	#[test]
	fn test_graph_weight() {
		global::set_local_chain_type(ChainTypes::Mainnet);

		// initial weights
		assert_eq!(graph_weight(1, 31), 256 * 31);
		assert_eq!(graph_weight(1, 32), 512 * 32);
		assert_eq!(graph_weight(1, 33), 1024 * 33);

		// one year in, 31 starts going down, the rest stays the same
		assert_eq!(graph_weight(YEAR_HEIGHT, 31), 256 * 30);
		assert_eq!(graph_weight(YEAR_HEIGHT, 32), 512 * 32);
		assert_eq!(graph_weight(YEAR_HEIGHT, 33), 1024 * 33);

		// 31 loses one factor per week
		assert_eq!(graph_weight(YEAR_HEIGHT + WEEK_HEIGHT, 31), 256 * 29);
		assert_eq!(graph_weight(YEAR_HEIGHT + 2 * WEEK_HEIGHT, 31), 256 * 28);
		assert_eq!(graph_weight(YEAR_HEIGHT + 32 * WEEK_HEIGHT, 31), 0);

		// 2 years in, 31 still at 0, 32 starts decreasing
		assert_eq!(graph_weight(2 * YEAR_HEIGHT, 31), 0);
		assert_eq!(graph_weight(2 * YEAR_HEIGHT, 32), 512 * 32);
		assert_eq!(graph_weight(2 * YEAR_HEIGHT, 33), 1024 * 33);

		// 32 phaseout on hold
		assert_eq!(
			graph_weight(2 * YEAR_HEIGHT + WEEK_HEIGHT, 32),
			C32_GRAPH_WEIGHT
		);
		assert_eq!(graph_weight(2 * YEAR_HEIGHT + WEEK_HEIGHT, 31), 0);
		assert_eq!(
			graph_weight(2 * YEAR_HEIGHT + 30 * WEEK_HEIGHT, 32),
			C32_GRAPH_WEIGHT
		);
		assert_eq!(
			graph_weight(2 * YEAR_HEIGHT + 31 * WEEK_HEIGHT, 32),
			C32_GRAPH_WEIGHT
		);

		// 3 years in, nothing changes
		assert_eq!(graph_weight(3 * YEAR_HEIGHT, 31), 0);
		assert_eq!(graph_weight(3 * YEAR_HEIGHT, 32), 512 * 32);
		assert_eq!(graph_weight(3 * YEAR_HEIGHT, 33), 1024 * 33);

		// 4 years in, still on hold
		assert_eq!(graph_weight(4 * YEAR_HEIGHT, 31), 0);
		assert_eq!(graph_weight(4 * YEAR_HEIGHT, 32), 512 * 32);
		assert_eq!(graph_weight(4 * YEAR_HEIGHT, 33), 1024 * 33);
		assert_eq!(graph_weight(4 * YEAR_HEIGHT, 33), 1024 * 33);
	}
}
