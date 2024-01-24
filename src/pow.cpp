// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <uint256.h>

const CBlockIndex* GetLastPoSBlockIndex(const CBlockIndex* pindex)
{
    while (pindex && pindex->pprev && pindex->IsProofOfWork())
        pindex = pindex->pprev;
    return pindex;
}

unsigned int GetNextWorkRequiredPoS(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    const int64_t T = params.nPosTargetSpacing;
    const int64_t N = 24;
    const int64_t k = N * (N + 1) * T / 2;
    const int64_t height = pindexLast->nHeight;
    const arith_uint256 posLimit = UintToArith256(params.posLimit);

    if (height < params.lastPoWBlock + N) { return posLimit.GetCompact(); }

    arith_uint256 sumTarget, nextTarget;
    int64_t thisTimestamp, previousTimestamp;
    int64_t t = 0, j = 0;

    const CBlockIndex* blockPreviousTimestamp = pindexLast->GetAncestor(height - N);
    previousTimestamp = blockPreviousTimestamp->GetBlockTime();

    // Loop through N most recent blocks.
    for (int64_t i = height - N + 1; i <= height; i++) {
        const CBlockIndex* block = pindexLast->GetAncestor(i);
        thisTimestamp = (block->GetBlockTime() > previousTimestamp) ?
                         block->GetBlockTime() : previousTimestamp + 1;
        int64_t solvetime = std::min(6 * T, thisTimestamp - previousTimestamp);
        previousTimestamp = thisTimestamp;
        j++;
        t += solvetime * j; // Weighted solvetime sum.
        arith_uint256 target;
        target.SetCompact(block->nBits);
        sumTarget += target / (k * N);
    }
    nextTarget = t * sumTarget;
    if (nextTarget > posLimit) { nextTarget = posLimit; }

    return nextTarget.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    if (pindexLast->nHeight + 1 > params.lastPoWBlock) {
        return GetNextWorkRequiredPoS(pindexLast, params);
    } else {
        if (Params().NetworkIDString() == CBaseChainParams::TESTNET) {
	    return nProofOfWorkLimit;
        }
        return GetNextWorkRequiredDigiShield(pindexLast, params);
    }

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval(pindexLast->nHeight+1) != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval(pindexLast->nHeight+1) != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval(pindexLast->nHeight+1)-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval(height) == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

/////////////////////////////////////////////////////////////////////////////////////////////

int64_t GetTargetSpacing(int nBestHeight, const Consensus::Params& params)
{
    return (int64_t) params.GetPowTargetSpacing(nBestHeight);
}

int64_t GetInterval(int nBestHeight, const Consensus::Params& params)
{
    return (int64_t) params.nPowTargetTimespan / GetTargetSpacing(nBestHeight, params);
}

unsigned int GetNextWorkRequiredDigiShield(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    const arith_uint256 bnProofOfWorkLimit = UintToArith256(params.powLimit);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    int blockstogoback = 0;
    int64_t retargetTimespan = params.GetPowTargetSpacing(pindexLast->nHeight+1);
    int64_t retargetSpacing = params.GetPowTargetSpacing(pindexLast->nHeight+1);
    int64_t retargetInterval = retargetTimespan / retargetSpacing;

    // Genesis block
    if (!pindexLast) {
	return nProofOfWorkLimit;
    }

    // Only change once per interval
    if ((pindexLast->nHeight+1) % retargetInterval != 0){
	return pindexLast->nBits;
    }

    // DigiByte: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    blockstogoback = retargetInterval - 1;
    if ((pindexLast->nHeight+1) != retargetInterval) {
	blockstogoback = retargetInterval;
    }

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++) {
	pindexFirst = pindexFirst->pprev;
    }
    assert(pindexFirst);

    // Limit adjustment step
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    if (nActualTimespan < (retargetTimespan - (retargetTimespan/4))) nActualTimespan = (retargetTimespan - (retargetTimespan/4));
    if (nActualTimespan > (retargetTimespan + (retargetTimespan/2))) nActualTimespan = (retargetTimespan + (retargetTimespan/2));

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= retargetTimespan;
    if (bnNew > bnProofOfWorkLimit) {
        bnNew = bnProofOfWorkLimit;
    }

    return bnNew.GetCompact();
}
