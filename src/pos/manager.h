// Copyright (c) 2023 Lynx Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef POS_STAKEMAN_H
#define POS_STAKEMAN_H

#include <logging.h>
#include <pos/minter.h>
#include <shutdown.h>
#include <util/time.h>

namespace wallet {
struct WalletContext;
class CWallet;
} // namespace wallet

extern bool fStakerRunning;
void stakeman_request_start();
void stakeman_request_stop();
void* stakeman_handler(wallet::WalletContext& wallet_context, ChainstateManager& chainman, CConnman* connman);

#endif // POS_STAKEMAN_H
