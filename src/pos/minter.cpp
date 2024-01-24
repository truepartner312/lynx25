// Copyright (c) 2017-2022 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/minter.h>

#include <chainparams.h>
#include <consensus/consensus.h>
#include <node/miner.h>
#include <pos/manager.h>
#include <pos/pos.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <shutdown.h>
#include <util/moneystr.h>
#include <util/syserror.h>
#include <util/thread.h>

#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <net.h>
#include <node/blockstorage.h>
#include <sync.h>
#include <timedata.h>
#include <validation.h>

#include <wallet/coinselection.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

#include <stdint.h>

// internal miner mutex
RecursiveMutex cs_mining_mutex;
bool mining_active{false};

std::vector<StakeThread*> vStakeThreads;

std::atomic<bool> fStopMinerProc(false);
std::atomic<bool> fTryToSync(false);
std::atomic<bool> fIsStaking(false);

int nMinStakeInterval = 0; // Minimum stake interval in seconds
int nMinerSleep = 500; // In milliseconds
std::atomic<int64_t> nTimeLastStake(0);

bool CheckStake(ChainstateManager& chainman, const CBlock* pblock)
{
    uint256 proofHash, hashTarget;
    uint256 hashBlock = pblock->GetHash();

    if (!pblock->IsProofOfStake()) {
        return error("%s: %s is not a proof-of-stake block.", __func__, hashBlock.GetHex());
    }

    if (!CheckStakeUnique(*pblock, false)) { // Check in SignBlock also
        return error("%s: %s CheckStakeUnique failed.", __func__, hashBlock.GetHex());
    }

    // Verify hash target and signature of coinstake tx
    {
        LOCK(cs_main);

        node::BlockMap::const_iterator mi = chainman.BlockIndex().find(pblock->hashPrevBlock);
        if (mi == chainman.BlockIndex().end()) {
            return error("%s: %s prev block not found: %s.", __func__, hashBlock.GetHex(), pblock->hashPrevBlock.GetHex());
        }

        if (!chainman.ActiveChain().Contains(&mi->second)) {
            return error("%s: %s prev block in active chain: %s.", __func__, hashBlock.GetHex(), pblock->hashPrevBlock.GetHex());
        }

        BlockValidationState state;
        if (!CheckProofOfStake(chainman.ActiveChainstate(), state, &mi->second, *pblock->vtx[1], pblock->nTime, pblock->nBits, proofHash, hashTarget)) {
            return error("%s: proof-of-stake checking failed.", __func__);
        }
        if (pblock->hashPrevBlock != chainman.ActiveChain().Tip()->GetBlockHash()) { // hashbestchain
            return error("%s: Generated block is stale.", __func__);
        }
    }

    // debug print
    LogPrintf("CheckStake(): New proof-of-stake block found  \n  hash: %s \nproofhash: %s  \ntarget: %s\n", hashBlock.GetHex(), proofHash.GetHex(), hashTarget.GetHex());

    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    if (!chainman.ProcessNewBlock(shared_pblock, true, /*min_pow_checked=*/true, nullptr)) {
        return error("%s: Block not accepted.", __func__);
    }

    return true;
}

void set_mining_thread_active() {
    LOCK(cs_mining_mutex);
    mining_active = true;
    LogPrintf("%s\n", __func__);
}

void set_mining_thread_inactive() {
    LOCK(cs_mining_mutex);
    mining_active = false;
    LogPrintf("%s\n", __func__);
}

bool is_mining_thread_active() {
    LOCK(cs_mining_mutex);
    return mining_active;
}

void StartThreadStakeMiner(wallet::WalletContext& wallet_context, ChainstateManager& chainman, CConnman* connman)
{
    nMinStakeInterval = gArgs.GetIntArg("-minstakeinterval", 0);
    nMinerSleep = gArgs.GetIntArg("-minersleep", 500);

    if (!gArgs.GetBoolArg("-staking", true)) {
        LogPrintf("Staking disabled\n");
    } else {
        auto vpwallets = GetWallets(wallet_context);
        size_t nWallets = vpwallets.size();

        if (nWallets < 1) {
            return;
        }
        size_t nThreads = std::min(nWallets, (size_t)gArgs.GetIntArg("-stakingthreads", 1));

        size_t nPerThread = nWallets / nThreads;
        for (size_t i = 0; i < nThreads; ++i) {
            size_t nStart = nPerThread * i;
            size_t nEnd = (i == nThreads - 1) ? nWallets : nPerThread * (i + 1);
            StakeThread* t = new StakeThread();
            vStakeThreads.push_back(t);
            vpwallets[i].get()->nStakeThread = i;
            t->sName = strprintf("miner%d", i);
            t->thread = std::thread(&util::TraceThread, t->sName.c_str(), std::function<void()>(std::bind(&ThreadStakeMiner, i, vpwallets, nStart, nEnd, &chainman, connman)));
        }
    }

    fStopMinerProc = false;
}

void StopThreadStakeMiner()
{
    if (vStakeThreads.size() < 1 || // no thread created
        fStopMinerProc) {
        return;
    }
    LogPrint(BCLog::POS, "StopThreadStakeMiner\n");
    fStopMinerProc = true;

    for (auto t : vStakeThreads) {
        t->m_thread_interrupt();
        t->thread.join();
        delete t;
    }
    vStakeThreads.clear();
}

void WakeThreadStakeMiner(wallet::CWallet* pwallet)
{
    size_t nStakeThread = 0;
    {
        LOCK(pwallet->cs_wallet);
        nStakeThread = pwallet->nStakeThread;
        if (nStakeThread >= vStakeThreads.size() || pwallet->IsScanning()) {
            return;
        }
        pwallet->nLastCoinStakeSearchTime = 0;
        LogPrint(BCLog::POS, "WakeThreadStakeMiner: wallet %s, thread %d\n", pwallet->GetName(), nStakeThread);
    }
    StakeThread* t = vStakeThreads[nStakeThread];
    t->m_thread_interrupt();
}

void WakeAllThreadStakeMiner()
{
    LogPrint(BCLog::POS, "WakeAllThreadStakeMiner\n");
    for (auto t : vStakeThreads) {
        t->m_thread_interrupt();
    }
}

bool ThreadStakeMinerStopped()
{
    return fStopMinerProc;
}

static inline void condWaitFor(size_t nThreadID, int ms)
{
    assert(vStakeThreads.size() > nThreadID);
    StakeThread* t = vStakeThreads[nThreadID];
    t->m_thread_interrupt.reset();
    t->m_thread_interrupt.sleep_for(std::chrono::milliseconds(ms));
}

bool SignBlockWithKey(CBlock& block, const CKey& key)
{
    std::vector<valtype> vSolutions;
    const CTxOut& txout = block.vtx[1]->vout[1];

    TxoutType whichType = Solver(txout.scriptPubKey, vSolutions);

    if (!key.Sign(block.GetHash(), block.vchBlockSig)) {
        LogPrint(BCLog::POS, "%s: signing block with key type %s failed\n", __func__, GetTxnOutputType(whichType));
        return false;
    }

    LogPrint(BCLog::POS, "%s: signing block with key type %s succeeded\n", __func__, GetTxnOutputType(whichType));

    return true;
}

bool SignBlock(CBlock& block, CBlockIndex* pindexPrev, wallet::CWallet* wallet, int nHeight, int64_t nSearchTime, Chainstate& chain_state)
{
    LogPrintf("%s: Height %d\n", __func__, nHeight);

    if (block.vtx.size() < 1) {
        return error("%s: Malformed block.", __func__);
    }

    CKey key;
    block.nBits = GetNextWorkRequiredPoS(pindexPrev, Params().GetConsensus());
    LogPrintf("%s: nBits %d\n", __func__, block.nBits);

    CAmount nFees = 0;
    CMutableTransaction txCoinStake;
    if (CreateCoinStake(wallet, pindexPrev, block.nBits, nSearchTime, nHeight, nFees, txCoinStake, key, chain_state)) {
        LogPrint(BCLog::POS, "%s: Kernel found.\n", __func__);

        if (nSearchTime >= pindexPrev->GetPastTimeLimit() + 1) {

            // make sure coinstake would meet timestamp protocol
            //    as it would be the same as the block timestamp
            block.nTime = nSearchTime;

            // Insert coinstake as vtx[1]
            block.vtx.insert(block.vtx.begin() + 1, MakeTransactionRef(txCoinStake));

            bool mutated;
            block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);

            uint256 blockhash = block.GetHash();
            LogPrint(BCLog::POS, "%s: signing blockhash %s\n", __func__, blockhash.ToString());

            // Append a signature to the block
            return SignBlockWithKey(block, key);
        }
    }

    wallet->nLastCoinStakeSearchTime = nSearchTime;

    return false;
}

void ThreadStakeMiner(size_t nThreadID, std::vector<std::shared_ptr<wallet::CWallet>>& vpwallets, size_t nStart, size_t nEnd, ChainstateManager* chainman, CConnman* connman)
{
    while (GetTime() - GetStartupTime() < 15) {
        UninterruptibleSleep(std::chrono::milliseconds { 150 });
        if (ShutdownRequested()) return;
    }

    LogPrintf("Starting staking thread %d, %d wallet%s.\n", nThreadID, nEnd - nStart, (nEnd - nStart) > 1 ? "s" : "");

    int nBestHeight; // TODO: set from new block signal?
    int64_t nBestTime;

    if (!gArgs.GetBoolArg("-staking", true)) {
        LogPrint(BCLog::POS, "%s: -staking is false.\n", __func__);
        return;
    }

    const bool stake_thread_ignore_peers = gArgs.GetBoolArg("-stakethreadignorepeers", false);
    const size_t stake_thread_cond_delay_ms = gArgs.GetIntArg("-stakethreadconddelayms", 60000);
    LogPrint(BCLog::POS, "Stake thread conditional delay set to %d.\n", stake_thread_cond_delay_ms);
    LogPrint(BCLog::POS, "Stake thread is %s peers.\n", stake_thread_ignore_peers ? "ignoring" : "not ignoring");

    while (!fStopMinerProc) {
        if (node::fReindex) {
            fIsStaking = false;
            LogPrint(BCLog::POS, "%s: Block import/reindex.\n", __func__);
            condWaitFor(nThreadID, 30000);
            continue;
        }

        if (!fStakerRunning) {
            condWaitFor(nThreadID, 5000);
            continue;
        }

        int num_nodes;
        {
            LOCK(cs_main);
            nBestHeight = chainman->ActiveChain().Height();
            nBestTime = chainman->ActiveChain().Tip()->nTime;
            num_nodes = connman->GetNodeCount(ConnectionDirection::Both);
        }

        if (is_mining_thread_active()) {
            fIsStaking = false;
            LogPrint(BCLog::POS, "%s: WaitingForMiningThread\n", __func__);
            condWaitFor(nThreadID, 2000);
            continue;
        }

        if (!stake_thread_ignore_peers && fTryToSync) {
            fTryToSync = false;
            if (num_nodes < 3 || chainman->ActiveChainstate().IsInitialBlockDownload()) {
                fIsStaking = false;
                LogPrint(BCLog::POS, "%s: TryToSync\n", __func__);
                condWaitFor(nThreadID, 30000);
                continue;
            }
        }

        if (!stake_thread_ignore_peers && (num_nodes == 0 || chainman->ActiveChainstate().IsInitialBlockDownload())) {
            fIsStaking = false;
            fTryToSync = true;
            LogPrint(BCLog::POS, "%s: IsInitialBlockDownload\n", __func__);
            condWaitFor(nThreadID, 2000);
            continue;
        }

        if (nMinStakeInterval > 0 && nTimeLastStake + (int64_t)nMinStakeInterval > GetTime()) {
            LogPrint(BCLog::POS, "%s: Rate limited to 1 / %d seconds.\n", __func__, nMinStakeInterval);
            condWaitFor(nThreadID, nMinStakeInterval * 500); // nMinStakeInterval / 2 seconds
            continue;
        }

        int64_t nTime = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
        int64_t nMask = nStakeTimestampMask;
        int64_t nSearchTime = nTime & ~nMask;
        if (nSearchTime <= nBestTime) {
            if (nTime < nBestTime) {
                LogPrint(BCLog::POS, "%s: Can't stake before last block time.\n", __func__);
                condWaitFor(nThreadID, std::min(1000 + (nBestTime - nTime) * 1000, (int64_t)30000));
                continue;
            }

            int64_t nNextSearch = nSearchTime + nMask;
            condWaitFor(nThreadID, std::min(nMinerSleep + (nNextSearch - nTime) * 1000, (int64_t)10000));
            continue;
        }

        std::unique_ptr<node::CBlockTemplate> pblocktemplate;

        size_t nWaitFor = stake_thread_cond_delay_ms;
        CAmount reserve_balance;

        for (size_t i = nStart; i < nEnd; ++i) {
            auto pwallet = vpwallets[i];

            if (!pwallet->fStakingEnabled) {
                pwallet->m_is_staking = wallet::CWallet::NOT_STAKING_DISABLED;
                continue;
            }

            {
                LOCK(pwallet->cs_wallet);
                if (nSearchTime <= pwallet->nLastCoinStakeSearchTime) {
                    nWaitFor = std::min(nWaitFor, (size_t)nMinerSleep);
                    continue;
                }

                if (pwallet->nStakeLimitHeight && nBestHeight >= pwallet->nStakeLimitHeight) {
                    pwallet->m_is_staking = wallet::CWallet::NOT_STAKING_LIMITED;
                    nWaitFor = std::min(nWaitFor, (size_t)30000);
                    continue;
                }

                if (pwallet->IsLocked()) {
                    pwallet->m_is_staking = wallet::CWallet::NOT_STAKING_LOCKED;
                    nWaitFor = std::min(nWaitFor, (size_t)30000);
                    continue;
                }
                reserve_balance = pwallet->nReserveBalance;
            }

            CAmount balance = GetSpendableBalance(*pwallet);

            if (balance <= reserve_balance) {
                LOCK(pwallet->cs_wallet);
                pwallet->m_is_staking = wallet::CWallet::NOT_STAKING_BALANCE;
                nWaitFor = std::min(nWaitFor, (size_t)60000);
                pwallet->nLastCoinStakeSearchTime = nSearchTime + stake_thread_cond_delay_ms / 1000;
                LogPrint(BCLog::POS, "%s: %s, low balance.\n", __func__, pwallet->GetName());
                continue;
            }

            if (!pblocktemplate.get()) {
                CScript dummyScript;
                pblocktemplate = node::BlockAssembler { chainman->ActiveChainstate(), chainman->ActiveChainstate().GetMempool() }.CreateNewBlock(dummyScript, true);
                if (!pblocktemplate.get()) {
                    fIsStaking = false;
                    nWaitFor = std::min(nWaitFor, (size_t)nMinerSleep);
                    LogPrint(BCLog::POS, "%s: Couldn't create new block.\n", __func__);
                    continue;
                }
            }

            pwallet->m_is_staking = wallet::CWallet::IS_STAKING;

            nWaitFor = nMinerSleep;
            fIsStaking = true;
            CBlock* pblock = &pblocktemplate->block;

            if (SignBlock(*pblock, chainman->ActiveChain().Tip(), pwallet.get(), nBestHeight + 1, nSearchTime, chainman->ActiveChainstate())) {
                if (CheckStake(*chainman, pblock)) {
                    nTimeLastStake = GetTime();
                    break;
                }
            } else {
                int nRequiredDepth = std::min((int)COINBASE_MATURITY, (int)(nBestHeight / 2));
                LOCK(pwallet->cs_wallet);
                if (pwallet->m_greatest_txn_depth < nRequiredDepth - 4) {
                    pwallet->m_is_staking = wallet::CWallet::NOT_STAKING_DEPTH;
                    size_t nSleep = (nRequiredDepth - pwallet->m_greatest_txn_depth) / 4;
                    nWaitFor = std::min(nWaitFor, (size_t)(nSleep * 1000));
                    pwallet->nLastCoinStakeSearchTime = nSearchTime + nSleep;
                    LogPrint(BCLog::POS, "%s: %s, no outputs with required depth. Sleeping for %ds.\n", __func__, pwallet->GetName(), nSleep);
                    continue;
                }
            }
        }

        condWaitFor(nThreadID, nWaitFor);
    }
}

bool SelectCoinsForStaking(wallet::CWallet* wallet, CAmount nTargetValue, std::set<std::pair<const wallet::CWalletTx*, unsigned int>>& setCoinsRet, CAmount& nValueRet)
{
    const Consensus::Params& params = Params().GetConsensus();

    // fetch suitable coins
    std::vector<wallet::COutput> vCoins;
    {
        LOCK(wallet->cs_wallet);
        auto res = wallet::AvailableCoins(*wallet);
        for (auto entry : res.All()) {
            vCoins.push_back(entry);
        }
    }

    setCoinsRet.clear();
    nValueRet = 0;

    for (const auto& output : vCoins) {
        const auto& txout = output.txout;
        int input_age = GetTime() - output.time;
        if (input_age < params.nStakeMinAge || input_age > params.nStakeMaxAge) {
            LogPrint(BCLog::POS, "not using %s: age params not met\n", txout.ToString());
            continue;
        }

        {
            LOCK(wallet->cs_wallet);
            COutPoint kernel(output.outpoint);
            if (!CheckStakeUnused(kernel) || wallet->IsLockedCoin(kernel)) {
                LogPrint(BCLog::POS, "not using %s: already used or coin is locked\n", txout.ToString());
                continue;
            }
        }

        {
            LOCK(wallet->cs_wallet);
            wallet::isminetype mine = wallet->IsMine(txout);
            if (!(mine & wallet::ISMINE_SPENDABLE)) {
                LogPrint(BCLog::POS, "not using %s: isnt mine/not spendable\n", txout.ToString());
                continue;
            }
        }

        // Stop if we've chosen enough inputs
        if (nValueRet >= nTargetValue) {
            break;
        }

        CAmount n = output.txout.nValue;
        std::pair<int64_t, std::pair<const wallet::CWalletTx*, unsigned int>> coin;
        {
            LOCK(wallet->cs_wallet);
            const wallet::CWalletTx* wtx = wallet->GetWalletTx(output.outpoint.hash);
            coin = std::make_pair(n, std::make_pair(wtx, output.outpoint.n));
        }

        if (n >= nTargetValue) {
            // If input value is greater or equal to target then simply insert
            //    it into the current subset and exit
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            break;
        } else {
            if (n < nTargetValue + CENT) {
                setCoinsRet.insert(coin.second);
                nValueRet += coin.first;
            }
        }
    }

    return true;
}

bool CreateCoinStake(wallet::CWallet* wallet, CBlockIndex* pindexPrev, unsigned int nBits, int64_t nTime, int nBlockHeight, int64_t nFees, CMutableTransaction& txNew, CKey& key, Chainstate& chain_state)
{
    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    CAmount nBalance = GetSpendableBalance(*wallet);
    if (nBalance <= wallet->nReserveBalance) {
        return false;
    }

    // Ensure txn is empty
    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));

    // Choose coins to use
    CAmount nValueIn = 0;
    std::vector<const wallet::CWalletTx*> vwtxPrev;
    std::set<std::pair<const wallet::CWalletTx*, unsigned int>> setCoins;
    if (!SelectCoinsForStaking(wallet, nBalance - wallet->nReserveBalance, setCoins, nValueIn)) {
        UninterruptibleSleep(std::chrono::milliseconds { 150 });
        return false;
    }

    if (setCoins.empty()) {
        UninterruptibleSleep(std::chrono::milliseconds { 150 });
        return false;
    }

    CAmount nCredit = 0;
    CScript scriptPubKeyKernel;
    std::set<std::pair<const wallet::CWalletTx*, unsigned int>>::iterator it = setCoins.begin();

    for (; it != setCoins.end(); ++it) {
        auto pcoin = *it;
        if (ThreadStakeMinerStopped()) {
            return false;
        }

        auto mempool = chain_state.GetMempool();
        if (!mempool->HasNoInputsOf(*pcoin.first->tx)) {
            continue;
        }

        int64_t nBlockTime;
        COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);
        if (CheckKernel(chain_state, pindexPrev, nBits, nTime, prevoutStake, &nBlockTime)) {
            LOCK(wallet->cs_wallet);

            // Found a kernel
            LogPrint(BCLog::POS, "%s: Kernel found.\n", __func__);

            CTxOut kernelOut = pcoin.first->tx->vout[pcoin.second];

            CScript scriptPubKeyOut;
            std::vector<valtype> vSolutions;
            CScript scriptPubKeyKernel = pcoin.first->tx->vout[pcoin.second].scriptPubKey;
            TxoutType whichType = Solver(scriptPubKeyKernel, vSolutions);

            LogPrint(BCLog::POS, "%s: parsed kernel type=%s\n", __func__, GetTxnOutputType(whichType));

            if (whichType == TxoutType::PUBKEYHASH || whichType == TxoutType::WITNESS_V0_KEYHASH)
            {
                uint160 hash160(vSolutions[0]);
                auto spk_man = wallet->GetLegacyScriptPubKeyMan();
                if (!spk_man) {
                    LogPrint(BCLog::POS, "%s: failed to get legacyscriptpubkeyman\n", __func__);
                    return false;
                }
                if (!spk_man->GetKey(CKeyID(hash160), key)) {
                    LogPrint(BCLog::POS, "%s: failed to get key for kernel type=%d\n", __func__, GetTxnOutputType(whichType));
                    return false;
                }
                scriptPubKeyOut << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;

            }
            else if (whichType == TxoutType::SCRIPTHASH)
            {
                uint160 hash160(vSolutions[0]);
                auto spk_man = wallet->GetLegacyScriptPubKeyMan();
                if (!spk_man) {
                    LogPrint(BCLog::POS, "%s: failed to get legacyscriptpubkeyman\n", __func__);
                    return false;
                }
                CKeyID keyID;
                CScript script;
                CTxDestination inner_dest;
                CScriptID scriptID(hash160);
                if (spk_man->GetCScript(scriptID, script) && ExtractDestination(script, inner_dest)) {
                    keyID = GetKeyForDestination(*spk_man, inner_dest);
                    if (!spk_man->GetKey(keyID, key)) {
                        LogPrint(BCLog::POS, "%s: failed to get key for kernel type=%d\n", __func__, GetTxnOutputType(whichType));
                        return false;
                    }
                }
            }
            else if (whichType == TxoutType::PUBKEY)
            {
                valtype& vchPubKey = vSolutions[0];
                CPubKey pubKey(vchPubKey);
                uint160 hash160(Hash160(vchPubKey));
                auto spk_man = wallet->GetLegacyScriptPubKeyMan();
                if (!spk_man) {
                    LogPrint(BCLog::POS, "%s: failed to get legacyscriptpubkeyman\n", __func__);
                    return false;
                }
                if (!spk_man->GetKey(CKeyID(hash160), key)) {
                    LogPrint(BCLog::POS, "%s: failed to get key for kernel type=%d\n", __func__, GetTxnOutputType(whichType));
                    return false;
                }
                scriptPubKeyOut << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;
            }
            else
            {
                LogPrint(BCLog::POS, "%s: no support for kernel type=%s\n", __func__, GetTxnOutputType(whichType));
                continue;
            }

            txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
            nCredit += pcoin.first->tx->vout[pcoin.second].nValue;
            vwtxPrev.push_back(pcoin.first);
            CTxOut out(0, scriptPubKeyOut);
            txNew.vout.push_back(out);

            LogPrint(BCLog::POS, "%s: Added kernel.\n", __func__);

            setCoins.erase(it);
            break;
        }
    }

    if (nCredit == 0 || nCredit > nBalance - wallet->nReserveBalance) {
        return false;
    }

    // Attempt to add more inputs
    // Only advantage here is to setup the next stake using this output as a kernel to have a higher chance of staking
    size_t nStakesCombined = 0;
    it = setCoins.begin();
    while (it != setCoins.end()) {
        if (nStakesCombined >= wallet->nMaxStakeCombine) {
            break;
        }

        // Stop adding more inputs if already too many inputs
        if (txNew.vin.size() >= 100) {
            break;
        }

        // Stop adding more inputs if value is already pretty significant
        if (nCredit >= wallet->nStakeCombineThreshold) {
            break;
        }

        std::set<std::pair<const wallet::CWalletTx*, unsigned int>>::iterator itc = it++; // copy the current iterator then increment it
        auto pcoin = *itc;
        CTxOut prevOut = pcoin.first->tx->vout[pcoin.second];

        // Only add coins of the same key/address as kernel
        if (prevOut.scriptPubKey != scriptPubKeyKernel) {
            continue;
        }

        // Stop adding inputs if reached reserve limit
        if (nCredit + prevOut.nValue > nBalance - wallet->nReserveBalance) {
            break;
        }

        // Do not add additional significant input
        if (prevOut.nValue >= wallet->nStakeCombineThreshold) {
            continue;
        }

        txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
        nCredit += pcoin.first->tx->vout[pcoin.second].nValue;
        vwtxPrev.push_back(pcoin.first);

        LogPrint(BCLog::POS, "%s: Combining kernel %s, %d.\n", __func__, pcoin.first->GetHash().ToString(), pcoin.second);
        nStakesCombined++;
        setCoins.erase(itc);
    }

    const Consensus::Params& consensusParams = Params().GetConsensus();

    // Get block reward
    CAmount nReward = GetProofOfStakeReward(pindexPrev->nHeight+1, consensusParams);
    if (nReward < 0) {
        return false;
    }

    nCredit += nReward;
    {
        if (nCredit >= wallet->nStakeSplitThreshold) {
            txNew.vout.push_back(CTxOut(0, txNew.vout[1].scriptPubKey));
        }

        // Set output amount
        if (txNew.vout.size() == 3) {
            txNew.vout[1].nValue = (nCredit / 2 / CENT) * CENT;
            txNew.vout[2].nValue = nCredit - txNew.vout[1].nValue;
        } else {
            txNew.vout[1].nValue = nCredit;
        }
    }

    // Sign
    int nIn = 0;
    for (const auto& pcoin : vwtxPrev) {
        uint32_t nPrev = txNew.vin[nIn].prevout.n;
        CTxOut prevOut = pcoin->tx->vout[nPrev];
        CAmount amount = prevOut.nValue;
        CScript& scriptPubKeyOut = prevOut.scriptPubKey;

        SignatureData sigdata;
        if (!ProduceSignature(*wallet->GetLegacyScriptPubKeyMan(), MutableTransactionSignatureCreator(txNew, nIn, amount, SIGHASH_ALL), scriptPubKeyOut, sigdata)) {
            return error("%s: ProduceSignature failed.", __func__);
        }

        UpdateInput(txNew.vin[nIn], sigdata);
        nIn++;
    }

    // Limit size
    unsigned int nBytes = ::GetSerializeSize(txNew, PROTOCOL_VERSION);
    if (nBytes >= MAX_BLOCK_SERIALIZED_SIZE / 5) {
        return error("%s: Exceeded coinstake size limit.", __func__);
    }

    // Successfully generated coinstake
    return true;
}
