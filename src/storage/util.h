// Copyright (c) 2023 Lynx Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STORAGE_UTIL_H
#define BITCOIN_STORAGE_UTIL_H

#include <validation.h>
#include <wallet/wallet.h>

using namespace wallet;

void set_wallet_context(WalletContext* wallet_context);
void set_chainman_context(ChainstateManager& chainman_context);
bool strip_opreturndata_from_chunk(std::string& opdata, std::string& chunk);
CTxOut build_opreturn_txout(std::string& payload);
void is_valid_chunk(std::string& chunk, int& type);
std::string unixtime_to_hexstring(uint32_t& time);
uint32_t hexstring_to_unixtime(std::string& time);
bool does_path_exist(std::string& path);
bool does_file_exist(std::string& filepath);
void strip_unknown_chars(std::string& input);
bool is_valid_uuid(std::string& uuid);

#endif // BITCOIN_STORAGE_UTIL_H
