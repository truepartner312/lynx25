// Copyright (c) 2023 Lynx Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STORAGE_AUTH_H
#define BITCOIN_STORAGE_AUTH_H

#include <key.h>
#include <key_io.h>

#include <opfile/src/decode.h>
#include <opfile/src/encode.h>
#include <opfile/src/protocol.h>
#include <opfile/src/util.h>
#include <storage/storage.h>
#include <storage/worker.h>

void add_auth_member(uint160 pubkeyhash);
void remove_auth_member(uint160 pubkeyhash);
void build_auth_list(const Consensus::Params& params);
bool is_auth_member(uint160 pubkeyhash);
bool set_auth_user(std::string& privatewif);
void copy_auth_list(std::vector<uint160>& tempList);
bool is_signature_valid_chunk(std::string chunk);
bool is_signature_valid_raw(std::vector<unsigned char>& signature, uint256& hash);
bool check_contextual_auth(std::string& chunk, int& error_level);
bool process_auth_chunk(std::string& chunk, int& error_level);
bool is_opreturn_an_authdata(const CScript& script_data, int& error_level);
bool found_opreturn_in_authdata(const CScript& script_data, int& error_level, bool test_accept = false);
bool does_tx_have_authdata(const CTransaction& tx);
bool scan_blocks_for_authdata(ChainstateManager& chainman);
bool check_mempool_for_authdata(const CTxMemPool& mempool);
bool generate_auth_payload(std::string& payload, int& type, uint32_t& time, std::string& hash);
bool generate_auth_transaction(WalletContext& wallet_context, CMutableTransaction& tx, std::string& opPayload);

#endif // BITCOIN_STORAGE_AUTH_H
