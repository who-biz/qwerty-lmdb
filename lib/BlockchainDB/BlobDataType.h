// Copyright (c) 2014-2018, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#ifndef BLOBDATATYPE_H
#define BLOBDATATYPE_H

#include "binary_archive.h"
#include "hex_str.h"
#include "Common/StringTools.h"

#pragma once

namespace CryptoNote
{
  typedef std::string blobdata;
}
/*
template<class t_object>
bool t_serializable_object_to_blob(const t_object& to, CryptoNote::blobdata& b_blob)
{
  std::stringstream ss;
  serial::binary_archive<false> ba(ss);
  std::vector<uint8_t> to_v = hex_to_vec(ss.str());
  bool r = serial::serialize(ba, to);
  b_blob = ss.str();
  return r;
}
  //---------------------------------------------------------------
  template<class t_object>
  CryptoNote::blobdata t_serializable_object_to_blob(const t_object& to)
  {
    CryptoNote::blobdata b;
    t_serializable_object_to_blob(to, b);
    return b;
  }
  //---------------------------------------------------------------
  CryptoNote::blobdata tx_to_blob(const CryptoNote::Transaction& tx)
  {
    return t_serializable_object_to_blob(tx);
  }
  //---------------------------------------------------------------
  bool block_to_blob(const CryptoNote::Block& b, CryptoNote::blobdata& b_blob)
  {
    return t_serializable_object_to_blob(b, b_blob);
  }
  //---------------------------------------------------------------
  CryptoNote::blobdata block_to_blob(const CryptoNote::Block& b)
  {
    return t_serializable_object_to_blob(b);
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const CryptoNote::blobdata& tx_blob, CryptoNote::Transaction& tx, Crypto::Hash& tx_hash, Crypto::Hash& tx_prefix_hash)
  {
    CryptoNote::blobdata bd = tx_to_blob(tx);
    if (bd.empty()) {
      return false;
    } else
       return true;
  }
  //---------------------------------------------------------------
   bool parse_and_validate_block_from_blob(const CryptoNote::blobdata& b_blob, CryptoNote::Block& b)
  {
    std::stringstream ss;
    ss << b_blob;
    std::vector<uint8_t> vec = hex_to_vec(ss.str());
    serial::binary_archive<false> ba(ss);
    bool r = serial::serialize(ba, b);
    if(!r)
      return false;
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const CryptoNote::blobdata& tx_blob, CryptoNote::Transaction& tx)
  {
    std::stringstream ss;
    ss << tx_blob;
    serial::binary_archive<false> ba(ss);
    bool r = serial::serialize(ba, tx);
    if (!r)
      return false;
    return true;
  }
*/
#endif //BLOBDATATYPE_H
