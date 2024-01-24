// Copyright (c) 2023 Lynx Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STORAGE_STORAGE_H
#define BITCOIN_STORAGE_STORAGE_H

#include <string.h>
#include <validation.h>

#include <wallet/wallet.h>

using namespace wallet;

bool scan_blocks_for_uuids(ChainstateManager& chainman, std::vector<std::string>& uuid_found);
bool scan_blocks_for_specific_uuid(ChainstateManager& chainman, std::string& uuid, int& error_level, std::vector<std::string>& chunks);
void estimate_coins_for_opreturn(CWallet* wallet, int& suitable_inputs);
bool select_coins_for_opreturn(CWallet* wallet, std::set<std::pair<const CWalletTx*, unsigned int>>& setCoinsRet, CAmount& valueRet);
bool generate_selfsend_transaction(WalletContext& wallet_context, CMutableTransaction& tx, std::vector<std::string>& opPayload);

#endif // BITCOIN_STORAGE_STORAGE_H
