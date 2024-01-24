// Copyright (c) 2023 Lynx Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <key_io.h>
#include <opfile/src/chunk.h>
#include <opfile/src/decode.h>
#include <opfile/src/protocol.h>
#include <pos/minter.h>
#include <primitives/transaction.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <storage/util.h>
#include <sync.h>
#include <validation.h>

#include <wallet/rpc/util.h>
#include <wallet/rpc/wallet.h>

#include <wallet/coinselection.h>
#include <wallet/context.h>
#include <wallet/fees.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

#include <vector>

using namespace node;
using namespace wallet;

bool scan_blocks_for_uuids(ChainstateManager& chainman, std::vector<std::string>& uuid_found)
{
    uuid_found.clear();
    const CChain& active_chain = chainman.ActiveChain();
    const int tip_height = active_chain.Height();

    // iterate all blocks
    CBlock block{};
    CBlockIndex* pindex = nullptr;
    for (int height = 1; height < tip_height; height++) {

        pindex = active_chain[height];
        if (!ReadBlockFromDisk(block, pindex, chainman.GetConsensus())) {
            return false;
        }

        for (unsigned int vtx = 0; vtx < block.vtx.size(); vtx++) {

            if (block.vtx[vtx]->IsCoinBase() || block.vtx[vtx]->IsCoinStake()) {
                continue;
            }

            for (unsigned int vout = 0; vout < block.vtx[vtx]->vout.size(); vout++) {

                if (block.vtx[vtx]->vout[vout].scriptPubKey.IsOpReturn()) {

                    std::string opdata, chunk, uuid;
                    opdata = HexStr(block.vtx[vtx]->vout[vout].scriptPubKey);
                    if (!strip_opreturndata_from_chunk(opdata, chunk)) {
                        //LogPrintf("%s - failed at strip_opreturndata_from_chunk\n", __func__);
                        continue;
                    }

                    int error_level, protocol;
                    if (!check_chunk_contextual(chunk, protocol, error_level)) {
                        //LogPrintf("%s - failed at check_chunk_contextual\n", __func__);
                        continue;
                    }

                    get_uuid_from_chunk(chunk, uuid);
                    if (std::find(uuid_found.begin(), uuid_found.end(), uuid) != uuid_found.end()) {
                        continue;
                    } else {
                        uuid_found.push_back(uuid);
                    }
                }
            }
        }
    }

    return true;
}

bool scan_blocks_for_specific_uuid(ChainstateManager& chainman, std::string& uuid, int& error_level, std::vector<std::string>& chunks)
{
    bool hasauth;
    chunks.clear();
    const CChain& active_chain = chainman.ActiveChain();
    const int tip_height = active_chain.Height();

    hasauth = false;

    // iterate all blocks
    CBlock block{};
    CBlockIndex* pindex = nullptr;
    for (int height = 1; height < tip_height; height++) {

        pindex = active_chain[height];
        if (!ReadBlockFromDisk(block, pindex, chainman.GetConsensus())) {
            return false;
        }

        for (unsigned int vtx = 0; vtx < block.vtx.size(); vtx++) {

            if (block.vtx[vtx]->IsCoinBase() || block.vtx[vtx]->IsCoinStake()) {
                continue;
            }

            for (unsigned int vout = 0; vout < block.vtx[vtx]->vout.size(); vout++) {

                if (block.vtx[vtx]->vout[vout].scriptPubKey.IsOpReturn()) {

                    std::string opdata, chunk, this_uuid;
                    opdata = HexStr(block.vtx[vtx]->vout[vout].scriptPubKey);
                    if (!strip_opreturndata_from_chunk(opdata, chunk)) {
                        //LogPrintf("%s - failed at strip_opreturndata_from_chunk\n", __func__);
                        continue;
                    }

                    int protocol;
                    if (!check_chunk_contextual(chunk, protocol, error_level)) {
                        //LogPrintf("%s - failed at check_chunk_contextual\n", __func__);
                        continue;
                    }

                    get_uuid_from_chunk(chunk, this_uuid);
                    if (uuid == this_uuid) {

                        // test for authchunk
                        int chunklen2;
                        std::string chunklen;
                        get_chunklen_from_chunk(chunk, chunklen);
                        chunklen2 = std::stoul(chunklen, nullptr, 16);
                        if (chunklen2 == 0) {
                            if (!is_valid_authchunk(chunk, error_level)) {
                                // pass error_level through
                                continue;
                            }
                            LogPrintf("found valid authchunk for uuid %s\n", this_uuid);
                            hasauth = true;
                            continue;
                        }

                        // chunktotal
                        int chunktotal2;
                        std::string chunktotal;
                        get_chunktotal_from_chunk(chunk, chunktotal);
                        chunktotal2 = std::stoul(chunktotal, nullptr, 16);

                        // resize vector
                        chunks.resize(chunktotal2);

                        // chunknum
                        int chunknum2;
                        std::string chunknum;
                        get_chunknum_from_chunk(chunk, chunknum);
                        chunknum2 = std::stoul(chunknum, nullptr, 16);

                        // put chunk in correct position
                        chunks[chunknum2-1] = chunk;
                    }
                }
            }
        }
    }

    // ...not present?
    if (!hasauth) {
        LogPrintf("couldnt find valid authchunk for uuid %s\n", uuid);
        error_level = ERR_CHUNKAUTHNONE;
        return false;
    }

    return true;
}

void estimate_coins_for_opreturn(CWallet* wallet, int& suitable_inputs)
{
    suitable_inputs = 0;

    std::vector<COutput> vCoins;
    {
        LOCK(wallet->cs_wallet);
        auto res = AvailableCoins(*wallet);
        for (auto entry : res.All()) {
            vCoins.push_back(entry);
        }
    }

    for (const auto& output : vCoins) {

        const auto& txout = output.txout;
        {
            LOCK(wallet->cs_wallet);

            COutPoint kernel(output.outpoint);
            if (wallet->IsLockedCoin(kernel)) {
                continue;
            }

            isminetype mine = wallet->IsMine(txout);
            if (!(mine & ISMINE_SPENDABLE)) {
                continue;
            }

            const CWalletTx* wtx = wallet->GetWalletTx(output.outpoint.hash);
            int depth = wallet->GetTxDepthInMainChain(*wtx);
            if (depth < COINBASE_MATURITY) {
                continue;
            }

            if (output.txout.nValue < 1 * COIN) {
                continue;
            }

            //LogPrintf("%s %d %llu LYNX\n", wtx->GetHash().ToString(), output.outpoint.n, output.txout.nValue);

            ++suitable_inputs;
        }
    }
}

bool select_coins_for_opreturn(CWallet* wallet, std::set<std::pair<const CWalletTx*, unsigned int>>& setCoinsRet, CAmount& valueRet)
{
    std::vector<COutput> vCoins;
    {
        LOCK(wallet->cs_wallet);
        auto res = AvailableCoins(*wallet);
        for (auto entry : res.All()) {
            vCoins.push_back(entry);
        }
    }

    setCoinsRet.clear();

    for (const auto& output : vCoins) {

        const auto& txout = output.txout;
        {
            LOCK(wallet->cs_wallet);

            COutPoint kernel(output.outpoint);
            if (wallet->IsLockedCoin(kernel)) {
                continue;
            }

            isminetype mine = wallet->IsMine(txout);
            if (!(mine & ISMINE_SPENDABLE)) {
                continue;
            }

            const CWalletTx* wtx = wallet->GetWalletTx(output.outpoint.hash);
            int depth = wallet->GetTxDepthInMainChain(*wtx);
            if (depth < COINBASE_MATURITY) {
                continue;
            }

            if (output.txout.nValue < 1 * COIN) {
                continue;
            }

            //LogPrintf("%s %d %llu LYNX\n", wtx->GetHash().ToString(), output.outpoint.n, output.txout.nValue);

            setCoinsRet.insert(std::make_pair(wtx, output.outpoint.n));
            valueRet = output.txout.nValue;

            return true;
        }
    }

    return false;
}

bool generate_selfsend_transaction(WalletContext& wallet_context, CMutableTransaction& tx, std::vector<std::string>& opPayload)
{
    auto vpwallets = GetWallets(wallet_context);
    size_t nWallets = vpwallets.size();
    if (nWallets < 1) {
        return false;
    }

    CAmount setValue;
    std::set<std::pair<const CWalletTx*, unsigned int>> setCoins;
    if (!select_coins_for_opreturn(vpwallets.front().get(), setCoins, setValue)) {
        return false;
    }

    if (setCoins.size() == 0) {
        return false;
    }

    // get vin/vout
    std::set<std::pair<const CWalletTx*, unsigned int>>::iterator it = setCoins.begin();
    COutPoint out{it->first->tx->GetHash(), it->second};
    CTxIn txIn(out);
    CScript receiver = it->first->tx->vout[0].scriptPubKey;
    CTxOut txOut(setValue, receiver);

    // build tx
    tx.nVersion = CTransaction::CURRENT_VERSION;
    tx.vin.push_back(txIn);
    tx.vout.push_back(txOut);

    // build opreturn(s)
    CTxOut txOpOut;
    for (auto& l : opPayload) {
        txOpOut = build_opreturn_txout(l);
        tx.vout.push_back(txOpOut);
    }

    {
        //! sign tx once to get complete size
        LOCK(vpwallets[0]->cs_wallet);
        if (!vpwallets[0]->SignTransaction(tx)) {
            return false;
        }

        // calculate and adjust fee (with 32byte fudge)
        unsigned int nBytes = GetSerializeSize(tx) + 32;
        CAmount nFee = GetRequiredFee(*vpwallets[0].get(), nBytes);
        tx.vout[0].nValue -= nFee;

        //! sign tx again with correct fee in place
        if (!vpwallets[0]->SignTransaction(tx)) {
            return false;
        }

        //! commit to wallet and relay to network
        CTransactionRef txRef = MakeTransactionRef(tx);
        vpwallets[0]->CommitTransaction(txRef, {}, {});
    }

    return true;
}
