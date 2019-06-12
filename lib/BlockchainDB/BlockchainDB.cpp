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
#include "../external/db_drivers/liblmdb/lmdb.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Hardfork.h"
#include <iostream>

#include "Lmdb/db_lmdb.h"

static const char *db_types[] = {
  "lmdb"
};

using namespace Common;
namespace CryptoNote
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
, "lmdb"
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

BlockchainLMDB *new_db(const std::string& db_type)
{
    return new BlockchainLMDB();
}


void BlockchainLMDB::init_options(boost::program_options::options_description& desc)
{
  command_line::add_arg(desc, arg_db_type);
  command_line::add_arg(desc, arg_db_sync_mode);
  command_line::add_arg(desc, arg_db_salvage);
}

void BlockchainLMDB::pop_block()
{
  Block blk;
  std::vector<Transaction> txs;
  pop_block(blk, txs);
}

void BlockchainLMDB::add_transaction(const Crypto::Hash& blk_hash, const Transaction& tx, const Crypto::Hash* tx_hash_ptr)
{
  bool miner_tx = false;
  Crypto::Hash tx_hash;
  if (!tx_hash_ptr)
  {
    // should only need to compute hash for miner Transactions
    tx_hash = getObjectHash(tx);
    //Logger(INFO, Logging::BRIGHT_GREEN) << "null tx_hash_ptr - needed to compute: " << tx_hash;
  }
  else
  {
    tx_hash = *tx_hash_ptr;
  }

  for (const TransactionInput& tx_input : tx.vin)
  {
    if (tx_input.type() == typeid(KeyInput))
    {
      add_spent_key(boost::get<KeyInput>(tx_input).keyImage);
    }
    else if (tx_input.type() == typeid(txin_gen))
    {
      /* nothing to do here */
      miner_tx = true;
    }
    else
    {
      //Logger(INFO, WHITE) << "Unsupported input type, removing key images and aborting transaction addition";
      for (const TransactionInput& tx_input : tx.vin)
      {
        if (tx_input.type() == typeid(KeyInput))
        {
          remove_spent_key(boost::get<KeyInput>(tx_input).keyImage);
        }
      }
      return;
    }
}
  uint64_t tx_id = add_transaction_data(blk_hash, tx, tx_hash);

}

uint64_t BlockchainLMDB::add_block( const Block& blk
                                , const size_t& block_size
                                , const difficulty_type& cumulative_difficulty
                                , const uint64_t& coins_generated
                                , const std::vector<std::pair<Transaction, BinaryArray>>& txs
                                )
{
  // sanity
  if (blk.txHashes.size() != txs.size())
    throw std::runtime_error("Inconsistent tx/hashes sizes");

  Crypto::Hash blk_hash = get_block_hash(blk);

  uint64_t prev_height = height();

  // call out to add the transactions

  add_transaction(blk_hash, blk.minerTx);
  int tx_i = 0;
  Crypto::Hash tx_hash = Crypto::null_hash;
  for (const Transaction& tx : txs)
  {
    tx_hash = blk.txHashes[tx_i];
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

void BlockchainLMDB::set_hard_fork(HardFork* hf)
{
  m_hardfork = hf;
}

void BlockchainLMDB::pop_block(Block& blk, std::vector<Transaction>& txs)
{
  blk = get_top_block();

  remove_block();

  for (const auto& h : boost::adaptors::reverse(blk.txHashes))
  {
    txs.push_back(get_tx(h));
    remove_transaction(h);
  }
  remove_transaction(getObjectHash(blk.minerTx));
}

bool BlockchainLMDB::is_open() const
{
  return m_open;
}

void BlockchainLMDB::remove_transaction(const Crypto::Hash& tx_hash)
{
  Transaction tx = get_tx(tx_hash);

  for (const TransactionInput& tx_input : tx.vin)
  {
    if (tx_input.type() == typeid(KeyInput))
    {
      remove_spent_key(boost::get<KeyInput>(tx_input).keyImage);
    }
  }

  // need tx as tx.vout has the tx outputs, and the output amounts are needed
  remove_transaction_data(tx_hash, tx);
}

Block BlockchainLMDB::get_block_from_height(const uint64_t& height) const
{
  BinaryArray bd = get_block_blob_from_height(height);
  Block b;
  //if (!parse_and_validate_block_from_blob(bd, b))
    //throw DB_ERROR("Failed to parse block from blob retrieved from the db");

  return b;
}

Block BlockchainLMDB::get_block(const Crypto::Hash& h) const
{
  BinaryArray bd = get_block_blob(h);
  Block b;
  //if (!parse_and_validate_block_from_blob(bd, b))
    //throw DB_ERROR("Failed to parse block from blob retrieved from the db");

  return b;
}

bool BlockchainLMDB::get_tx(const Crypto::Hash& h, CryptoNote::Transaction &tx) const
{
  BinaryArray bd;
  if (!get_tx_blob(h, bd))
    return false;
  //if (!parse_and_validate_tx_from_blob(bd, tx))
    //throw DB_ERROR("Failed to parse transaction from blob retrieved from the db");

  return true;
}

Transaction BlockchainLMDB::get_tx(const Crypto::Hash& h) const
{
  Transaction tx;
  //if (!get_tx(h, tx))
    //throw TX_DNE(std::string("tx with hash ").append(Common::podToHex(h)).append(" not found in db").c_str());
  return tx;
}

void BlockchainLMDB::fixup()
{
  if (is_read_only()) {
    //Logger(INFO, WHITE) << "Database is opened read only - skipping fixup check";
    return;
  }

  set_batch_transactions(false);
  batch_start();
  batch_stop();
}

}  // namespace cryptonote
