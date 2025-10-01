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

//! Definition of the genesis block. Placeholder for now.

// required for genesis replacement
//! #![allow(unused_imports)]

use crate::consensus::Difficulty;
use crate::core;
use crate::core::hash::Hash;
use crate::global;
use crate::pow::{mine_genesis_block, RandomXProofOfWork};
use chrono::prelude::{TimeZone, Utc};
use grin_util::secp::constants::SINGLE_BULLET_PROOF_SIZE;
use grin_util::secp::pedersen::{Commitment, RangeProof};
use grin_util::secp::Signature;
use keychain::BlindingFactor;

/// Genesis block definition for development networks. The proof of work size
/// is small enough to mine it on the fly, so it does not contain its own
/// proof of work solution. Can also be easily mutated for different tests.
pub fn genesis_dev() -> core::Block {
	core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.with_ymd_and_hms(1997, 8, 4, 0, 0, 0).unwrap(),
		pow: RandomXProofOfWork {
			nonce: 0, // Hardcoded nonce for dev (replace with mined value if needed)
			total_difficulty: Difficulty::zero(),
			cache: None,
		},
		..Default::default()
	})
}

/// Testnet genesis block
pub fn genesis_test() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.with_ymd_and_hms(2018, 12, 28, 20, 48, 4).unwrap(),
		prev_root: Hash::from_hex(
			"00000000000000000017ff4903ef366c8f62e3151ba74e41b8332a126542f538",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"73b5e0a05ea9e1e4e33b8f1c723bc5c10d17f07042c2af7644f4dbb61f4bc556",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"667a3ba22f237a875f67c9933037c8564097fa57a3e75be507916de28fc0da26",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"cfdddfe2d938d0026f8b1304442655bbdddde175ff45ddf44cb03bcb0071a72d",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: RandomXProofOfWork {
			nonce: 23, // Hardcoded nonce for testnet
			total_difficulty: Difficulty::from_num(10_u64.pow(5)),
			cache: None,
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(
			grin_util::from_hex(
				"08df2f1d996cee37715d9ac0a0f3b13aae508d1101945acb8044954aee30960be9",
			)
			.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			25, 176, 52, 246, 172, 1, 12, 220, 247, 111, 73, 101, 13, 16, 157, 130, 110, 196, 123,
			217, 246, 137, 45, 110, 106, 186, 0, 151, 255, 193, 233, 178, 103, 26, 210, 215, 200,
			89, 146, 188, 9, 161, 28, 212, 227, 143, 82, 54, 5, 223, 16, 65, 237, 132, 196, 241,
			39, 76, 133, 45, 252, 131, 88, 0,
		])
		.unwrap(),
	};
	let output = core::Output::new(
		core::OutputFeatures::Coinbase,
		Commitment::from_vec(
			grin_util::from_hex(
				"08c12007af16d1ee55fffe92cef808c77e318dae70c3bc70cb6361f49d517f1b68",
			)
			.unwrap(),
		),
	);
	gen.with_reward(output, kernel)
}

/// Mainnet genesis block
pub fn genesis_main() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.with_ymd_and_hms(2019, 1, 15, 16, 1, 26).unwrap(),
		prev_root: Hash::from_hex(
			"0000000000000000002a8bc32f43277fe9c063b9c99ea252b483941dcd06e217",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"fa7566d275006c6c467876758f2bc87e4cebd2020ae9cf9f294c6217828d6872",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"1b7fff259aee3edfb5867c4775e4e1717826b843cda6685e5140442ece7bfc2e",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"e8bb096a73cbe6e099968965f5342fc1702ee2802802902286dcf0f279e326bf",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: RandomXProofOfWork {
			nonce: 41, // Hardcoded nonce for mainnet
			total_difficulty: Difficulty::from_num(2_u64.pow(34)),
			cache: None,
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(
			grin_util::from_hex(
				"096385d86c5cfda718aa0b7295be0adf7e5ac051edfe130593a2a257f09f78a3b1",
			)
			.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			80, 208, 41, 171, 28, 224, 250, 121, 60, 192, 213, 232, 111, 199, 111, 105, 18, 22, 54,
			165, 107, 33, 186, 113, 186, 100, 12, 42, 72, 106, 42, 20, 67, 253, 188, 178, 228, 246,
			21, 168, 253, 18, 22, 179, 41, 63, 250, 218, 80, 132, 75, 67, 244, 11, 108, 27, 188,
			251, 212, 166, 233, 103, 117, 237, 194, 102, 96, 205, 24,
		])
		.unwrap(),
	};
	let output = core::Output::new(
		core::OutputFeatures::Coinbase,
		Commitment::from_vec(
			grin_util::from_hex(
				"08b7e57c448db5ef25aa119dde2312c64d7ff1b890c416c6dda5ec73cbfed2edea",
			)
			.unwrap(),
		),
	);
	gen.with_reward(output, kernel)
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hashed;
	use crate::ser::{self, ProtocolVersion};
	use grin_util::ToHex;

	#[test]
	fn testnet_genesis_hash() {
		global::set_local_chain_type(global::ChainTypes::Testnet);
		let gen = genesis_test();
		let gen_hash = gen.hash();
		println!("testnet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&gen, ProtocolVersion(1)).unwrap();
		println!("testnet genesis full hash: {}\n", gen_bin.hash().to_hex());
		// Update assert with your new hash
		assert_eq!(
			gen_hash.to_hex(),
			"edc758c1370d43e1d733f70f58cf187c3be8242830429b1676b89fd91ccf2dab"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"91c638fc019a54e6652bd6bb3d9c5e0c17e889cef34a5c28528e7eb61a884dc4"
		);
	}

	#[test]
	fn mainnet_genesis_hash() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		let gen = genesis_main();
		let gen_hash = gen.hash();
		println!("mainnet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&gen, ProtocolVersion(1)).unwrap();
		println!("mainnet genesis full hash: {}\n", gen_bin.hash().to_hex());
		// Update assert with your new hash
		assert_eq!(
			gen_hash.to_hex(),
			"40adad0aec27797b48840aa9e00472015c21baea118ce7a2ff1a82c0f8f5bf82"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"6be6f34b657b785e558e85cc3b8bdb5bcbe8c10e7e58524c8027da7727e189ef"
		);
	}
}
