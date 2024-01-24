// Copyright (c) 2017-2022 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_POS_MINER_H
#define PARTICL_POS_MINER_H

#include <primitives/transaction.h>
#include <util/threadinterrupt.h>
#include <thread>

#include <atomic>
#include <string>
#include <vector>

namespace wallet {
struct WalletContext;
class CWallet;
} // namespace wallet

class Chainstate;
class ChainstateManager;
class CBlockIndex;
class CBlock;
class CKey;
class CConnman;
class CMutableTransaction;

class StakeThread {
public:
    StakeThread() {};
    std::thread thread;
    std::string sName;
    CThreadInterrupt m_thread_interrupt;
};

typedef std::vector<unsigned char> valtype;

extern std::vector<StakeThread*> vStakeThreads;

extern std::atomic<bool> fIsStaking;
extern std::atomic<bool> fTryToSync;

extern int nMinStakeInterval;
extern int nMinerSleep;

void set_mining_thread_active();
void set_mining_thread_inactive();

bool CheckStake(ChainstateManager& chainman, const CBlock* pblock);

void StartThreadStakeMiner(wallet::WalletContext& wallet_context, ChainstateManager& chainman, CConnman* connman);
void StopThreadStakeMiner();
/**
 * Wake the thread from a possible long sleep
 * Should be called if chain is synced, wallet unlocked or balance/settings changed
 */
void WakeThreadStakeMiner(wallet::CWallet* pwallet);
void WakeAllThreadStakeMiner();
bool ThreadStakeMinerStopped();

void ThreadStakeMiner(size_t nThreadID, std::vector<std::shared_ptr<wallet::CWallet>>& vpwallets, size_t nStart, size_t nEnd, ChainstateManager* chainman, CConnman* connman);
bool CreateCoinStake(wallet::CWallet* wallet, CBlockIndex* pindexPrev, unsigned int nBits, int64_t nTime, int nBlockHeight, int64_t nFees, CMutableTransaction& txNew, CKey& key, Chainstate& chain_state);

#endif // PARTICL_POS_MINER_H
