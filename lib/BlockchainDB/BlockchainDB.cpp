// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <boost/range/adaptor/reversed.hpp>

#include "Common/StringTools.h"
#include "BlockchainDB.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"

#include "Lmdb/db_lmdb.h"

static const char *db_types[] = {
  "lmdb",
  nullptr*
};


using Common::PodToHex;

namespace cryptonote
{

bool blockchain_valid_db_type(const std::string& db_type)
{
  int i;
  for (i=0; db_types[i]; i++)
  {
    if (db_types[i] == db_type)
      return true;
  }
  return false;
}

std::string blockchain_db_types(const std::string& sep)
{
  int i;
  std::string ret = "";
  for (i=0; db_types[i]; i++)
  {
    if (i)
      ret += sep;
    ret += db_types[i];
  }
  return ret;
}

std::string arg_db_type_description = "Specify database type, available: " + CryptoNote::blockchain_db_types(", ");
const command_line::arg_descriptor<std::string> arg_db_type = {
  "db-type"
, arg_db_type_description.c_str()
, DEFAULT_DB_TYPE
};
const command_line::arg_descriptor<std::string> arg_db_sync_mode = {
  "db-sync-mode"
, "Specify sync option, using format [safe|fast|fastest]:[sync|async]:[nblocks_per_sync]." 
, "fast:async:1000"
};
const command_line::arg_descriptor<bool> arg_db_salvage  = {
  "db-salvage"
, "Try to salvage a blockchain database if it seems corrupted"
, false
};

BlockchainDB *new_db(const std::string& db_type)
{
  if (db_type == "lmdb")
    return new BlockchainLMDB();
  return NULL;
}

void BlockchainDB::init_options(boost::program_options::options_description& desc)
{
  command_line::add_arg(desc, arg_db_type);
  command_line::add_arg(desc, arg_db_sync_mode);
  command_line::add_arg(desc, arg_db_salvage);
}

void BlockchainDB::pop_block()
{
  block blk;
  std::vector<Transaction> txs;
  pop_block(blk, txs);
}

void BlockchainDB::add_Transaction(const Crypto::Hash& blk_hash, const std::pair<Transaction, blobdata>& txp, const Crypto::Hash* tx_hash_ptr, const Crypto::Hash* tx_prunable_hash_ptr)
{
  bool miner_tx = false;
  crypto::Hash tx_hash;
  if (!tx_hash_ptr)
  {
    // should only need to compute hash for miner Transactions
    tx_hash = getTransactionHash(tx);
    Logger(INFO, Logging::BRIGHT_GREEN) << "null tx_hash_ptr - needed to compute: " << tx_hash;
  }
  else
  {
    tx_hash = *tx_hash_ptr;
  }

  for (const txin_v& tx_input : tx.vin)
  {
    if (tx_input.type() == typeid(txin_to_key))
    {
      add_spent_key(boost::get<txin_to_key>(tx_input).k_image);
    }
    else if (tx_input.type() == typeid(txin_gen))
    {
      /* nothing to do here */
      miner_tx = true;
    }
    else
    {
      LOG_PRINT_L1("Unsupported input type, removing key images and aborting transaction addition");
      for (const txin_v& tx_input : tx.vin)
      {
        if (tx_input.type() == typeid(txin_to_key))
        {
          remove_spent_key(boost::get<txin_to_key>(tx_input).k_image);
        }
      }
      return;
    }
  }

  uint64_t tx_id = add_transaction_data(blk_hash, tx, tx_hash);

  std::vector<uint64_t> amount_output_indices;

  // iterate tx.vout using indices instead of C++11 foreach syntax because
  // we need the index
  for (uint64_t i = 0; i < tx.vout.size(); ++i)
  {
      amount_output_indices.push_back(add_output(tx_hash, tx.vout[i], i, tx.unlock_time, &tx.rct_signatures.outPk[i].mask));
  }
  add_tx_amount_output_indices(tx_id, amount_output_indices);
}

uint64_t BlockchainDB::add_block( const block& blk
                                , const size_t& block_size
                                , const difficulty_type& cumulative_difficulty
                                , const uint64_t& coins_generated
                                , const std::vector<std::pair<Transaction, BinaryArray>>& txs
                                )
{
  // sanity
  if (blk.tx_hashes.size() != txs.size())
    throw std::runtime_error("Inconsistent tx/hashes sizes");

  Crypto::Hash blk_hash = get_block_hash(blk);

  uint64_t prev_height = height();

  // call out to add the transactions

  add_transaction(blk_hash, blk.miner_tx);
  int tx_i = 0;
  Crypto::Hash tx_hash = crypto::null_hash;
  for (const transaction& tx : txs)
  {
    tx_hash = blk.tx_hashes[tx_i];
    add_transaction(blk_hash, tx, &tx_hash);
    ++tx_i;
  }

  // call out to subclass implementation to add the block & metadata
  add_block(blk, block_size, cumulative_difficulty, coins_generated, blk_hash);

  m_hardfork->add(blk, prev_height);

  block_txn_stop();

  ++num_calls;

  return prev_height;
}

void BlockchainDB::set_hard_fork(HardFork* hf)
{
  m_hardfork = hf;
}

void BlockchainDB::pop_block(block& blk, std::vector<Transaction>& txs)
{
  blk = get_top_block();

  remove_block();

  for (const auto& h : boost::adaptors::reverse(blk.tx_hashes))
  {
    txs.push_back(get_tx(h));
    remove_transaction(h);
  }
  remove_transaction(get_transaction_hash(blk.miner_tx));
}

bool BlockchainDB::is_open() const
{
  return m_open;
}

void BlockchainDB::remove_transaction(const Crypto::Hash& tx_hash)
{
  transaction tx = get_tx(tx_hash);

  for (const txin_v& tx_input : tx.vin)
  {
    if (tx_input.type() == typeid(txin_to_key))
    {
      remove_spent_key(boost::get<txin_to_key>(tx_input).k_image);
    }
  }

  // need tx as tx.vout has the tx outputs, and the output amounts are needed
  remove_transaction_data(tx_hash, tx);
}

block BlockchainDB::get_block_from_height(const uint64_t& height) const
{
  blobdata bd = get_block_blob_from_height(height);
  block b;
  if (!parse_and_validate_block_from_blob(bd, b))
    throw DB_ERROR("Failed to parse block from blob retrieved from the db");

  return b;
}

block BlockchainDB::get_block(const Crypto::Hash& h) const
{
  blobdata bd = get_block_blob(h);
  block b;
  if (!parse_and_validate_block_from_blob(bd, b))
    throw DB_ERROR("Failed to parse block from blob retrieved from the db");

  return b;
}

bool BlockchainDB::get_tx(const Crypto::Hash& h, CryptoNote::Transaction &tx) const
{
  blobdata bd;
  if (!get_tx_blob(h, bd))
    return false;
  if (!parse_and_validate_tx_from_blob(bd, tx))
    throw DB_ERROR("Failed to parse transaction from blob retrieved from the db");

  return true;
}

Transaction BlockchainDB::get_tx(const Crypto::Hash& h) const
{
  transaction tx;
  if (!get_tx(h, tx))
    throw TX_DNE(std::string("tx with hash ").append(epee::string_tools::pod_to_hex(h)).append(" not found in db").c_str());
  return tx;
}

void BlockchainDB::fixup()
{
  if (is_read_only()) {
    LOG_PRINT_L1("Database is opened read only - skipping fixup check");
    return;
  }

  set_batch_transactions(false);
  batch_start();
  batch_stop();
}

}  // namespace cryptonote
