// Copyright (c) 2014-2019, The Monero Project
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
#pragma once

#include <atomic>

#include <boost/thread/tss.hpp>
#include "../external/db_drivers/liblmdb/lmdb.h"
#include "BlockchainDB/Structures.h"
#include "BlockchainDB/BlobDataType.h"
#include "BlockchainDB/BlockchainDB.h"

typedef struct mdb_txn_cursors
{
  MDB_cursor *m_txc_blocks;
  MDB_cursor *m_txc_block_heights;
  MDB_cursor *m_txc_block_info;

  MDB_cursor *m_txc_output_txs;
  MDB_cursor *m_txc_output_amounts;

  MDB_cursor *m_txc_txs;
  MDB_cursor *m_txc_tx_indices;
  MDB_cursor *m_txc_tx_outputs;

  MDB_cursor *m_txc_spent_keys;

  MDB_cursor *m_txc_txpool_meta;
  MDB_cursor *m_txc_txpool_blob;

  MDB_cursor *m_txc_hf_versions;
} mdb_txn_cursors;

#define m_cur_blocks	m_cursors->m_txc_blocks
#define m_cur_block_heights	m_cursors->m_txc_block_heights
#define m_cur_block_info	m_cursors->m_txc_block_info
#define m_cur_output_txs	m_cursors->m_txc_output_txs
#define m_cur_output_amounts	m_cursors->m_txc_output_amounts
#define m_cur_txs	m_cursors->m_txc_txs
#define m_cur_tx_indices	m_cursors->m_txc_tx_indices
#define m_cur_tx_outputs	m_cursors->m_txc_tx_outputs
#define m_cur_spent_keys	m_cursors->m_txc_spent_keys
#define m_cur_txpool_meta	m_cursors->m_txc_txpool_meta
#define m_cur_txpool_blob	m_cursors->m_txc_txpool_blob
#define m_cur_hf_versions	m_cursors->m_txc_hf_versions

typedef struct mdb_rflags
{
  bool m_rf_txn;
  bool m_rf_blocks;
  bool m_rf_block_heights;
  bool m_rf_block_info;
  bool m_rf_output_txs;
  bool m_rf_output_amounts;
  bool m_rf_txs;
  bool m_rf_tx_indices;
  bool m_rf_tx_outputs;
  bool m_rf_spent_keys;
  bool m_rf_txpool_meta;
  bool m_rf_txpool_blob;
  bool m_rf_hf_versions;
} mdb_rflags;

typedef struct mdb_threadinfo
{
  MDB_txn *m_ti_rtxn;	// per-thread read txn
  mdb_txn_cursors m_ti_rcursors;	// per-thread read cursors
  mdb_rflags m_ti_rflags;	// per-thread read state

  ~mdb_threadinfo();
} mdb_threadinfo;

struct mdb_txn_safe
{
  mdb_txn_safe(const bool check=true);
  ~mdb_txn_safe();

  void commit(std::string message = "");

  // This should only be needed for batch transaction which must be ensured to
  // be aborted before mdb_env_close, not after. So we can't rely on
  // BlockchainLMDB destructor to call mdb_txn_safe destructor, as that's too late
  // to properly abort, since mdb_env_close would have been called earlier.
  void abort();
  void uncheck();

  operator MDB_txn*()
  {
    return m_txn;
  }

  operator MDB_txn**()
  {
    return &m_txn;
  }

  uint64_t num_active_tx() const;

  static void prevent_new_txns();
  static void wait_no_active_txns();
  static void allow_new_txns();

  mdb_threadinfo* m_tinfo;
  MDB_txn* m_txn;
  bool m_check;
  static std::atomic<uint64_t> num_active_txns;

  // could use a mutex here, but this should be sufficient.
  static std::atomic_flag creation_gate;
};

namespace CryptoNote {

class BlockchainLMDB : public BlockchainDB
{
public:

  BlockchainLMDB();
  virtual ~BlockchainLMDB();

  friend class BlockchainDB;

  virtual void open(const std::string& filename, const int mdb_flags=0);

  virtual void close();

  virtual void sync();

  virtual void safesyncmode(const bool onoff);

  virtual void reset();

  virtual std::vector<std::string> get_filenames() const;

  virtual std::string get_db_name() const;

  virtual bool lock();

  virtual void unlock();

  virtual bool block_exists(const Crypto::Hash& h, uint64_t *height = nullptr) const;

  virtual uint64_t get_block_height(const Crypto::Hash& h) const;

  virtual CryptoNote::BlockHeader get_block_header(const Crypto::Hash& h) const;

  virtual CryptoNote::blobdata get_block_blob(const Crypto::Hash& h) const;

  virtual CryptoNote::blobdata get_block_blob_from_height(const uint64_t& height) const;

  virtual uint64_t get_block_timestamp(const uint64_t& height) const;

  virtual uint64_t get_top_block_timestamp() const;

  virtual size_t get_block_size(const uint64_t& height) const;

  virtual CryptoNote::difficulty_type get_block_cumulative_difficulty(const uint64_t& height) const;

  virtual CryptoNote::difficulty_type get_block_difficulty(const uint64_t& height) const;

  virtual uint64_t get_block_already_generated_coins(const uint64_t& height) const;

  virtual Crypto::Hash get_block_hash_from_height(const uint64_t& height) const;

  virtual std::vector<CryptoNote::Block> get_blocks_range(const uint64_t& h1, const uint64_t& h2) const;

  virtual std::vector<Crypto::Hash> get_hashes_range(const uint64_t& h1, const uint64_t& h2) const;

  virtual Crypto::Hash top_block_hash() const;

  virtual CryptoNote::Block get_top_block() const;

  virtual uint64_t height() const;

  virtual bool tx_exists(const Crypto::Hash& h) const;
  virtual bool tx_exists(const Crypto::Hash& h, uint64_t& tx_index) const;

  virtual uint64_t get_tx_unlock_time(const Crypto::Hash& h) const;

  virtual bool get_tx_blob(const Crypto::Hash& h, CryptoNote::blobdata &tx) const;

  virtual uint64_t get_tx_count() const;

  virtual std::vector<CryptoNote::Transaction> get_tx_list(const std::vector<Crypto::Hash>& hlist) const;

  virtual uint64_t get_tx_block_height(const Crypto::Hash& h) const;

  virtual uint64_t get_num_outputs(const uint64_t& amount) const;

  virtual output_data_t get_output_key(const uint64_t& amount, const uint64_t& index);
  virtual output_data_t get_output_key(const uint64_t& global_index) const;
//  virtual void get_output_key(const uint64_t &amount, const std::vector<uint64_t> &offsets, std::vector<output_data_t> &outputs, bool allow_partial = false);

  virtual tx_out_index get_output_tx_and_index_from_global(const uint64_t& index) const;
  virtual void get_output_tx_and_index_from_global(const std::vector<uint64_t> &global_indices,
      std::vector<tx_out_index> &tx_out_indices) const;

  virtual tx_out_index get_output_tx_and_index(const uint64_t& amount, const uint64_t& index) const;
  virtual void get_output_tx_and_index(const uint64_t& amount, const std::vector<uint64_t> &offsets, std::vector<tx_out_index> &indices) const;

  virtual std::vector<uint64_t> get_tx_amount_output_indices(const uint64_t tx_id) const;

  virtual bool has_key_image(const Crypto::KeyImage& img) const;

  virtual void add_txpool_tx(const CryptoNote::Transaction &tx, const txpool_tx_meta_t& meta);
  virtual void update_txpool_tx(const Crypto::Hash &txid, const txpool_tx_meta_t& meta);
 // virtual uint64_t get_txpool_tx_count(bool include_unrelayed_txes = true) const;
  virtual uint64_t get_txpool_tx_count() const;

  virtual bool txpool_has_tx(const Crypto::Hash &txid) const;
  virtual void remove_txpool_tx(const Crypto::Hash& txid);
  virtual bool get_txpool_tx_meta(const Crypto::Hash& txid, txpool_tx_meta_t &meta) const;
  virtual bool get_txpool_tx_blob(const Crypto::Hash& txid, CryptoNote::blobdata &bd) const;
  virtual CryptoNote::blobdata get_txpool_tx_blob(const Crypto::Hash& txid) const;
  virtual bool for_all_txpool_txes(std::function<bool(const Crypto::Hash&, const txpool_tx_meta_t&, const CryptoNote::blobdata*)> f, bool include_blob = false, bool include_unrelayed_txes = true) const;

  virtual bool for_all_key_images(std::function<bool(const Crypto::KeyImage&)>) const;
  virtual bool for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const Crypto::Hash&, const CryptoNote::Block&)>) const;
  virtual bool for_all_transactions(std::function<bool(const Crypto::Hash&, const CryptoNote::Transaction&)>) const;
  virtual bool for_all_outputs(std::function<bool(uint64_t amount, const Crypto::Hash &tx_hash, uint64_t height, size_t tx_idx)> f) const;
  virtual bool for_all_outputs(uint64_t amount, const std::function<bool(uint64_t height)> &f) const;


  virtual uint64_t add_block( const CryptoNote::Block& blk
                            , const size_t& block_size
                            , const CryptoNote::difficulty_type& cumulative_difficulty
                            , const uint64_t& coins_generated
                            , const std::vector<CryptoNote::Transaction>& txs
                            );


  virtual void block_txn_start(bool readonly);
  virtual void block_txn_stop();
  virtual void block_txn_abort();
  virtual bool block_rtxn_start(MDB_txn **mtxn, mdb_txn_cursors **mcur) const;
  virtual void block_rtxn_stop() const;

  virtual void pop_block(CryptoNote::Block& blk, std::vector<CryptoNote::Transaction>& txs);

  virtual bool can_thread_bulk_indices() const { return true; }

  /**
   * @brief return a histogram of outputs on the blockchain
   *
   * @param amounts optional set of amounts to lookup
   * @param unlocked whether to restrict count to unlocked outputs
   * @param recent_cutoff timestamp to determine which outputs are recent
   *
   * @return a set of amount/instances
   */
  std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff) const;

private:

  virtual void add_block( const CryptoNote::Block& blk
                , const size_t& block_size
                , const CryptoNote::difficulty_type& cumulative_difficulty
                , const uint64_t& coins_generated
                , const Crypto::Hash& block_hash
                );

  virtual void remove_block();

  virtual uint64_t add_transaction_data(const Crypto::Hash& blk_hash, const CryptoNote::Transaction& tx, const Crypto::Hash& tx_hash);

  virtual void remove_transaction_data(const Crypto::Hash& tx_hash, const CryptoNote::Transaction& tx);

  virtual uint64_t add_output(const Crypto::Hash& tx_hash,
      const CryptoNote::TransactionOutput& tx_output,
      const uint64_t& local_index,
      const uint64_t unlock_time
      );

  virtual void add_tx_amount_output_indices(const uint64_t tx_id,
      const std::vector<uint64_t>& amount_output_indices
      );

  void remove_tx_outputs(const uint64_t tx_id, const CryptoNote::Transaction& tx);

  void remove_output(const uint64_t amount, const uint64_t& out_index);

  virtual void add_spent_key(const Crypto::KeyImage& k_image);

  virtual void remove_spent_key(const Crypto::KeyImage& k_image);

  uint64_t num_outputs() const;

  virtual void set_hard_fork_version(uint64_t height, uint8_t version);
  virtual uint8_t get_hard_fork_version(uint64_t height) const;
  virtual void drop_hard_fork_info();

  /**
   * @brief convert a tx output to a blob for storage
   *
   * @param output the output to convert
   *
   * @return the resultant blob
   */
  CryptoNote::blobdata output_to_blob(const CryptoNote::TransactionOutput& output) const;

  /**
   * @brief convert a tx output blob to a tx output
   *
   * @param blob the blob to convert
   *
   * @return the resultant tx output
   */
  CryptoNote::TransactionOutput output_from_blob(const CryptoNote::blobdata& blob) const;

  void check_open() const;

  virtual bool is_read_only() const;

  // fix up anything that may be wrong due to past bugs
  virtual void fixup();

  // migrate from older DB version to current
  void migrate(const uint32_t oldversion);

  // migrate from DB version 0 to 1
  void migrate_0_1();


private:
  bool m_open;

  MDB_env* m_env;

  MDB_dbi m_blocks;
  MDB_dbi m_block_heights;
  MDB_dbi m_block_info;

  MDB_dbi m_txs;
  MDB_dbi m_tx_indices;
  MDB_dbi m_tx_outputs;

  MDB_dbi m_output_txs;
  MDB_dbi m_output_amounts;

  MDB_dbi m_spent_keys;

  MDB_dbi m_txpool_meta;
  MDB_dbi m_txpool_blob;

  MDB_dbi m_hf_starting_heights;
  MDB_dbi m_hf_versions;

  MDB_dbi m_properties;

  mutable uint64_t m_cum_size;	// used in batch size estimation
  mutable unsigned int m_cum_count;
  std::string m_folder;
  mdb_txn_safe* m_write_txn; // may point to either a short-lived txn or a batch txn

  mdb_txn_cursors m_wcursors;
  mutable boost::thread_specific_ptr<mdb_threadinfo> m_tinfo;

  constexpr static uint64_t DEFAULT_MAPSIZE = 1LL << 33;

}; // class BlockchainLMDB

} // namespace CryptoNote

