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

//! JSON-RPC Stub generation for the Foreign API

use crate::core::core::hash::Hash;
use crate::core::core::transaction::Transaction;
use crate::foreign::Foreign;
use crate::pool::PoolEntry;
use crate::rest::Error;
use crate::types::{
	BlockHeaderPrintable, BlockListing, BlockPrintable, LocatedTxKernel, OutputListing,
	OutputPrintable, Tip, Version,
};
use crate::util;

/// Public definition used to generate Node jsonrpc api.
/// * When running `grin` with defaults, the V2 api is available at
/// `localhost:3413/v2/foreign`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc_mw::rpc]
pub trait ForeignRpc: Sync + Send {
	/**
	Networked version of [Foreign::get_header](struct.Foreign.html#method.get_header).
	*/
	fn get_header(
		&self,
		height: Option<u64>,
		hash: Option<String>,
		commit: Option<String>,
	) -> Result<BlockHeaderPrintable, Error>;

	/**
	Networked version of [Foreign::get_block](struct.Foreign.html#method.get_block).
	*/
	fn get_block(
		&self,
		height: Option<u64>,
		hash: Option<String>,
		commit: Option<String>,
	) -> Result<BlockPrintable, Error>;

	/**
	Networked version of [Foreign::get_blocks](struct.Foreign.html#method.get_blocks).
	*/
	fn get_blocks(
		&self,
		start_height: u64,
		end_height: u64,
		max: u64,
		include_proof: Option<bool>,
	) -> Result<BlockListing, Error>;

	/**
	Networked version of [Foreign::get_version](struct.Foreign.html#method.get_version).
	*/
	fn get_version(&self) -> Result<Version, Error>;

	/**
	Networked version of [Foreign::get_tip](struct.Foreign.html#method.get_tip).
	*/
	fn get_tip(&self) -> Result<Tip, Error>;

	/**
	Networked version of [Foreign::get_kernel](struct.Foreign.html#method.get_kernel).
	*/
	fn get_kernel(
		&self,
		excess: String,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<LocatedTxKernel, Error>;

	/**
	Networked version of [Foreign::get_outputs](struct.Foreign.html#method.get_outputs).
	*/
	fn get_outputs(
		&self,
		commits: Option<Vec<String>>,
		start_height: Option<u64>,
		end_height: Option<u64>,
		include_proof: Option<bool>,
		include_merkle_proof: Option<bool>,
	) -> Result<Vec<OutputPrintable>, Error>;

	/**
	Networked version of [Foreign::get_unspent_outputs](struct.Foreign.html#method.get_unspent_outputs).
	*/
	fn get_unspent_outputs(
		&self,
		start_index: u64,
		end_index: Option<u64>,
		max: u64,
		include_proof: Option<bool>,
	) -> Result<OutputListing, Error>;

	/**
	Networked version of [Foreign::get_pmmr_indices](struct.Foreign.html#method.get_pmmr_indices).
	*/
	fn get_pmmr_indices(
		&self,
		start_block_height: u64,
		end_block_height: Option<u64>,
	) -> Result<OutputListing, Error>;

	/**
	Networked version of [Foreign::get_pool_size](struct.Foreign.html#method.get_pool_size).
	*/
	fn get_pool_size(&self) -> Result<usize, Error>;

	/**
	Networked version of [Foreign::get_stempool_size](struct.Foreign.html#method.get_stempool_size).
	*/
	fn get_stempool_size(&self) -> Result<usize, Error>;

	/**
	Networked version of [Foreign::get_unconfirmed_transactions](struct.Foreign.html#method.get_unconfirmed_transactions).
	*/
	fn get_unconfirmed_transactions(&self) -> Result<Vec<PoolEntry>, Error>;

	/**
	Networked version of [Foreign::push_transaction](struct.Foreign.html#method.push_transaction).
	*/
	fn push_transaction(&self, tx: Transaction, fluff: Option<bool>) -> Result<(), Error>;
}

impl ForeignRpc for Foreign {
	fn get_header(
		&self,
		height: Option<u64>,
		hash: Option<String>,
		commit: Option<String>,
	) -> Result<BlockHeaderPrintable, Error> {
		let parsed_hash = hash
			.map(|s| util::from_hex(&s))
			.transpose()
			.map_err(|e| Error::Argument(format!("Invalid block hash: {}", e)))?
			.map(|v| Hash::from_vec(&v));
		self.get_header(height, parsed_hash, commit)
	}

	fn get_block(
		&self,
		height: Option<u64>,
		hash: Option<String>,
		commit: Option<String>,
	) -> Result<BlockPrintable, Error> {
		let parsed_hash = hash
			.map(|s| util::from_hex(&s))
			.transpose()
			.map_err(|e| Error::Argument(format!("Invalid block hash: {}", e)))?
			.map(|v| Hash::from_vec(&v));
		self.get_block(height, parsed_hash, commit)
	}

	fn get_blocks(
		&self,
		start_height: u64,
		end_height: u64,
		max: u64,
		include_proof: Option<bool>,
	) -> Result<BlockListing, Error> {
		self.get_blocks(start_height, end_height, max, include_proof)
	}

	fn get_version(&self) -> Result<Version, Error> {
		self.get_version()
	}

	fn get_tip(&self) -> Result<Tip, Error> {
		self.get_tip()
	}

	fn get_kernel(
		&self,
		excess: String,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<LocatedTxKernel, Error> {
		self.get_kernel(excess, min_height, max_height)
	}

	fn get_outputs(
		&self,
		commits: Option<Vec<String>>,
		start_height: Option<u64>,
		end_height: Option<u64>,
		include_proof: Option<bool>,
		include_merkle_proof: Option<bool>,
	) -> Result<Vec<OutputPrintable>, Error> {
		self.get_outputs(
			commits,
			start_height,
			end_height,
			include_proof,
			include_merkle_proof,
		)
	}

	fn get_unspent_outputs(
		&self,
		start_index: u64,
		end_index: Option<u64>,
		max: u64,
		include_proof: Option<bool>,
	) -> Result<OutputListing, Error> {
		self.get_unspent_outputs(start_index, end_index, max, include_proof)
	}

	fn get_pmmr_indices(
		&self,
		start_block_height: u64,
		end_block_height: Option<u64>,
	) -> Result<OutputListing, Error> {
		self.get_pmmr_indices(start_block_height, end_block_height)
	}

	fn get_pool_size(&self) -> Result<usize, Error> {
		self.get_pool_size()
	}

	fn get_stempool_size(&self) -> Result<usize, Error> {
		self.get_stempool_size()
	}

	fn get_unconfirmed_transactions(&self) -> Result<Vec<PoolEntry>, Error> {
		self.get_unconfirmed_transactions()
	}

	fn push_transaction(&self, tx: Transaction, fluff: Option<bool>) -> Result<(), Error> {
		self.push_transaction(tx, fluff)
	}
}

// Note: The doctest macro is commented out and not causing errors, so it’s left as-is.
#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:expr, $expected_response:expr) => {
		// create temporary grin server, run jsonrpc request on node api, delete server, return
		// json response.
		{
			/*use grin_servers::test_framework::framework::run_doctest;
			use grin_util as util;
			use serde_json;
			use serde_json::Value;
			use tempfile::tempdir;

			let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
			let dir = dir
				.path()
				.to_str()
				.ok_or("Failed to convert tmpdir path to string.".to_owned())
				.unwrap();

			let request_val: Value = serde_json::from_str($request).unwrap();
			let expected_response: Value = serde_json::from_str($expected_response).unwrap();
			let response = run_doctest(
				request_val,
				dir,
				$use_token,
				$blocks_to_mine,
				$perform_tx,
				$lock_tx,
				$finalize_tx,
			)
			.unwrap()
			.unwrap();
			if response != expected_response {
				panic!(
					"(left != right) \nleft: {}\nright: {}",
					serde_json::to_string_pretty(&response).unwrap(),
					serde_json::to_string_pretty(&expected_response).unwrap()
				);
			}*/
		}
	};
}
