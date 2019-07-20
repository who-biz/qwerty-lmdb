#ifndef STRUCTURES_H
#define STRUCTURES_H

#include "CryptoNoteCore/TransactionPool.h"

#pragma once

#pragma pack(push, 1)
struct output_data_t
{
  Crypto::PublicKey pubkey;       //!< the output's public key (for spend verification)
  uint64_t           unlock_time;  //!< the output's unlock time (or height)
  uint64_t           height;       //!< the height of the block which created the output
};
#pragma pack(pop)

#pragma pack(push, 1)
struct tx_data_t
{
  uint64_t tx_id;
  uint64_t unlock_time;
  uint64_t block_id;
};
#pragma pack(pop)

typedef std::pair<Crypto::Hash, uint64_t> tx_out_index;
typedef CryptoNote::tx_memory_pool::TransactionDetails txpool_tx_meta_t;
#endif // STRUCTURES_H

