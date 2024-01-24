// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2014 The BlackCoin developers
// Copyright (c) 2017-2022 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/pos.h>

#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <hash.h>
#include <node/transaction.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <txmempool.h>
#include <util/system.h>
#include <validation.h>

std::list<COutPoint> listStakeSeen;
std::map<COutPoint, uint256> mapStakeSeen;

/* Calculate the difficulty for a given block index.
 * Duplicated from rpc/blockchain.cpp for linking
 */
static double GetDifficulty(const CBlockIndex* blockindex)
{
    CHECK_NONFATAL(blockindex);

    int nShift = (blockindex->nBits >> 24) & 0xff;
    double dDiff = (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

double GetPoSKernelPS(CBlockIndex* pindex)
{
    LOCK(cs_main);

    CBlockIndex* pindexPrevStake = nullptr;

    int nBestHeight = pindex->nHeight;

    int nPoSInterval = 72; // blocks sampled
    double dStakeKernelsTriedAvg = 0;
    int nStakesHandled = 0, nStakesTime = 0;

    while (pindex && nStakesHandled < nPoSInterval) {
        if (pindex->IsProofOfStake()) {
            if (pindexPrevStake) {
                dStakeKernelsTriedAvg += GetDifficulty(pindexPrevStake) * 4294967296.0;
                nStakesTime += pindexPrevStake->nTime - pindex->nTime;
                nStakesHandled++;
            }
            pindexPrevStake = pindex;
        }
        pindex = pindex->pprev;
    }

    double result = 0;

    if (nStakesTime) {
        result = dStakeKernelsTriedAvg / nStakesTime;
    }

    result *= nStakeTimestampMask + 1;

    return result;
}

/**
 * Stake Modifier (hash modifier of proof-of-stake):
 * The purpose of stake modifier is to prevent a txout (coin) owner from
 * computing future proof-of-stake generated by this txout at the time
 * of transaction confirmation. To meet kernel protocol, the txout
 * must hash with a future stake modifier to generate the proof.
 */
uint256 ComputeStakeModifier(const CBlockIndex* pindexPrev, const uint256& kernel)
{
    if (!pindexPrev)
        return uint256(); // genesis block's modifier is 0

    CDataStream ss(SER_GETHASH, 0);
    ss << kernel << pindexPrev->nStakeModifier;
    return Hash(ss);
}

/**
 * BlackCoin kernel protocol
 * coinstake must meet hash target according to the protocol:
 * kernel (input 0) must meet the formula
 *     hash(nStakeModifier + txPrev.block.nTime + txPrev.nTime + txPrev.vout.hash + txPrev.vout.n + nTime) < bnTarget * nWeight
 * this ensures that the chance of getting a coinstake is proportional to the
 * amount of coins one owns.
 * The reason this hash is chosen is the following:
 *   nStakeModifier: scrambles computation to make it very difficult to precompute
 *                   future proof-of-stake
 *   txPrev.block.nTime: prevent nodes from guessing a good timestamp to
 *                       generate transaction for future advantage,
 *                       obsolete since v3
 *   txPrev.nTime: slightly scrambles computation
 *   txPrev.vout.hash: hash of txPrev, to reduce the chance of nodes
 *                     generating coinstake at the same time
 *   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
 *                  generating coinstake at the same time
 *   nTime: current timestamp
 *   block/tx hash should not be used here as they can be generated in vast
 *   quantities so as to generate blocks faster, degrading the system back into
 *   a proof-of-work situation.
 */
bool CheckStakeKernelHash(const CBlockIndex* pindexPrev,
    uint32_t nBits, uint32_t nBlockFromTime,
    CAmount prevOutAmount, const COutPoint& prevout, uint32_t nTime,
    uint256& hashProofOfStake, uint256& targetProofOfStake,
    bool fPrintProofOfStake)
{
    // CheckStakeKernelHash

    if (nTime < nBlockFromTime) { // Transaction timestamp violation
        return error("%s: nTime violation", __func__);
    }

    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0) {
        return error("%s: SetCompact failed.", __func__);
    }

    // Weighted target
    int64_t nValueIn = prevOutAmount;
    arith_uint256 bnWeight = arith_uint256(nValueIn);
    bnTarget *= bnWeight;

    targetProofOfStake = ArithToUint256(bnTarget);

    const uint256& nStakeModifier = pindexPrev->nStakeModifier;
    int nStakeModifierHeight = pindexPrev->nHeight;
    int64_t nStakeModifierTime = pindexPrev->nTime;

    CDataStream ss(SER_GETHASH, 0);
    ss << nStakeModifier;
    ss << nBlockFromTime << prevout.hash << prevout.n << nTime;
    hashProofOfStake = Hash(ss);

    if (fPrintProofOfStake) {
        LogPrintf("%s: using modifier=%s at height=%d timestamp=%s\n",
            __func__, nStakeModifier.ToString(), nStakeModifierHeight,
            FormatISO8601DateTime(nStakeModifierTime));
        LogPrintf("%s: check modifier=%s nTimeKernel=%u nPrevout=%u nTime=%u hashProof=%s\n",
            __func__, nStakeModifier.ToString(),
            nBlockFromTime, prevout.n, nTime,
            hashProofOfStake.ToString());
    }

    // Now check if proof-of-stake hash meets target protocol
    if (UintToArith256(hashProofOfStake) > bnTarget) {
        return false;
    }

    if (LogAcceptCategory(BCLog::POS, BCLog::Level::Debug) && !fPrintProofOfStake) {
        LogPrintf("%s: using modifier=%s at height=%d timestamp=%s\n",
            __func__, nStakeModifier.ToString(), nStakeModifierHeight,
            FormatISO8601DateTime(nStakeModifierTime));
        LogPrintf("%s: pass modifier=%s nTimeKernel=%u nPrevout=%u nTime=%u hashProof=%s\n",
            __func__, nStakeModifier.ToString(),
            nBlockFromTime, prevout.n, nTime,
            hashProofOfStake.ToString());
    }

    return true;
}

bool CheckProofOfStake(Chainstate& chain_state, BlockValidationState& state, const CBlockIndex* pindexPrev, const CTransaction& tx, int64_t nTime, unsigned int nBits, uint256& hashProofOfStake, uint256& targetProofOfStake)
{
    // pindexPrev is the current tip, the block the new block will connect on to
    // nTime is the time of the new/next block

    auto& pblocktree { chain_state.m_blockman.m_block_tree_db };

    if (!tx.IsCoinStake() || tx.vin.size() < 1) {
        LogPrintf("ERROR: %s: malformed-txn %s\n", __func__, tx.GetHash().ToString());
        return false;
    }

    CTransactionRef txPrev;

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx.vin[0];

    uint32_t nBlockFromTime;
    int nDepth;
    CScript kernelPubKey;
    CAmount amount;

    Coin coin;
    if (!chain_state.CoinsTip().GetCoin(txin.prevout, coin) || coin.IsSpent()) {
        return false;
    }

    CBlockIndex* pindex = chain_state.m_chain[coin.nHeight];
    if (!pindex) {
        return false;
    }

    nDepth = pindexPrev->nHeight - coin.nHeight;
    int nRequiredDepth = std::min((int)COINBASE_MATURITY, (int)(pindexPrev->nHeight / 2));
    if (nRequiredDepth > nDepth) {
        return false;
    }

    kernelPubKey = coin.out.scriptPubKey;
    amount = coin.out.nValue;
    nBlockFromTime = pindex->GetBlockTime();

    const CScript& scriptSig = txin.scriptSig;
    const CScriptWitness* witness = &txin.scriptWitness;
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<uint8_t> vchAmount(8);

    if (!VerifyScript(scriptSig, kernelPubKey, witness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&tx, 0, amount, MissingDataBehavior::FAIL), &serror)) {
        LogPrintf("ERROR: %s: verify-script-failed, txn %s, reason %s\n", __func__, tx.GetHash().ToString(), ScriptErrorString(serror));
        return false;
    }

    if (!CheckStakeKernelHash(pindexPrev, nBits, nBlockFromTime,
            amount, txin.prevout, nTime, hashProofOfStake, targetProofOfStake, LogAcceptCategory(BCLog::POS, BCLog::Level::Debug))) {
        LogPrintf("WARNING: %s: Check kernel failed on coinstake %s, hashProof=%s\n", __func__, tx.GetHash().ToString(), hashProofOfStake.ToString());
        return false;
    }

    return true;
}

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock)
{
    return (nTimeBlock & nStakeTimestampMask) == 0;
}

// Used only when staking, not during validation
bool CheckKernel(Chainstate& chain_state, const CBlockIndex* pindexPrev, unsigned int nBits, int64_t nTime, const COutPoint& prevout, int64_t* pBlockTime)
{
    uint256 hashProofOfStake, targetProofOfStake;

    Coin coin;
    {
        LOCK(::cs_main);
        if (!chain_state.CoinsTip().GetCoin(prevout, coin)) {
            return error("%s: prevout not found", __func__);
        }
    }
    if (coin.IsSpent()) {
        return error("%s: prevout is spent", __func__);
    }

    CBlockIndex* pindex = chain_state.m_chain[coin.nHeight];
    if (!pindex) {
        return false;
    }

    int nRequiredDepth = std::min((int)COINBASE_MATURITY, (int)(pindexPrev->nHeight / 2));
    int nDepth = pindexPrev->nHeight - coin.nHeight;

    if (nRequiredDepth > nDepth) {
        return false;
    }
    if (pBlockTime) {
        *pBlockTime = pindex->GetBlockTime();
    }

    CAmount amount = coin.out.nValue;
    return CheckStakeKernelHash(pindexPrev, nBits, *pBlockTime,
        amount, prevout, nTime, hashProofOfStake, targetProofOfStake);
}

bool AddToMapStakeSeen(const COutPoint& kernel, const uint256& blockHash)
{
    // Overwrites existing values

    std::pair<std::map<COutPoint, uint256>::iterator, bool> ret;
    ret = mapStakeSeen.insert(std::pair<COutPoint, uint256>(kernel, blockHash));
    if (ret.second == false) { // existing element
        ret.first->second = blockHash;
    } else {
        listStakeSeen.push_back(kernel);
    }

    return true;
};

bool CheckStakeUnused(const COutPoint& kernel)
{
    std::map<COutPoint, uint256>::const_iterator mi = mapStakeSeen.find(kernel);
    return (mi == mapStakeSeen.end());
}

bool CheckStakeUnique(const CBlock& block, bool fUpdate)
{
    LOCK(cs_main);

    uint256 blockHash = block.GetHash();
    const COutPoint& kernel = block.vtx[0]->vin[0].prevout;

    std::map<COutPoint, uint256>::const_iterator mi = mapStakeSeen.find(kernel);
    if (mi != mapStakeSeen.end()) {
        if (mi->second == blockHash) {
            return true;
        }
        return error("%s: Stake kernel for %s first seen on %s.", __func__, blockHash.ToString(), mi->second.ToString());
    }

    if (!fUpdate) {
        return true;
    }

    while (listStakeSeen.size() > 1024) {
        const COutPoint& oldest = listStakeSeen.front();
        if (1 != mapStakeSeen.erase(oldest)) {
            LogPrintf("%s: Warning: mapStakeSeen did not erase %s %n\n", __func__, oldest.hash.ToString(), oldest.n);
        }
        listStakeSeen.pop_front();
    }

    return AddToMapStakeSeen(kernel, blockHash);
};
