// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <consensus/amount.h>
#include <uint256.h>

#include <chrono>
#include <limits>
#include <map>
#include <vector>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_DERSIG; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

struct HFLynxParams {
    int height;
    int param;
};

struct BlackAddressInfo {
    int height;
    std::string address;

    CAmount minTransferToWhiteAddress;

    /* We'll must to allow the transfer to another address,
       otherwise the balance will not be able to charge. */
    CAmount maxTransferToOtherAddress;

    CAmount maxTransactionFee;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    int HardForkHeight;
    /** Block number at which the second hard fork will be performed */
    int HardFork2Height;
    /** Block number at which the third hard fork (DigiShield) will be performed */
    int HardFork3Height;

    /** Position of prev block that address must not win block (see rule1) depending on height */
    std::vector<struct HFLynxParams> HardForkRule1params;

    /** Power for calculating the minimum balance of the wallet (see pos rule2) depending on height */
    std::vector<struct HFLynxParams> HardForkRule2params;
    /** Position of prev block to get difficulty from (see rule2) */
    int HardForkRule2DifficultyPrevBlockCount;
    /** The lower limit of the minimum balance of the address */
    CAmount HardForkRule2LowerLimitMinBalance;
    /** The upper limit of the minimum balance of the address */
    CAmount HardForkRule2UpperLimitMinBalance;

    /** Number of chars to check in address and block hash (see pos rule3) depending on height */
    std::vector<struct HFLynxParams> HardForkRule3params;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t PowTargetSpacingV1;
    int64_t PowTargetSpacingV2;
    int64_t PowTargetSpacingV3;
    int64_t GetPowTargetSpacing(int nHeight) const {
        if (nHeight <= HardForkHeight)
            return PowTargetSpacingV1;
        if (nHeight <= HardFork2Height)
            return PowTargetSpacingV2;
        return PowTargetSpacingV3;
    }
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval(int nHeight) const { return nPowTargetTimespan / GetPowTargetSpacing(nHeight); }
    /** Proof of stake parameters */
    uint256 posLimit;
    int64_t nPosTargetSpacing;
    int64_t nPosTargetTimespan;
    int nStakeMinAge{0};
    int nStakeMaxAge{0};
    int lastPoWBlock{0};
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;
    /** Lynx initial authlist data */
    uint160 initAuthUser;
    uint32_t initAuthTime{0};

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
    /* From black addresses it is allowed to transfer coins only to the white address */
    std::vector<BlackAddressInfo> BlackAdresses;
    std::string WhiteAddress;
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
