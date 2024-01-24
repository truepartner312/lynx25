// Copyright (c) 2023 Lynx Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <storage/auth.h>
#include <storage/chunk.h>
#include <storage/util.h>
#include <wallet/fees.h>

using namespace node;

uint160 authUser;
uint32_t authTime{0};
std::string authUserKey;

RecursiveMutex authListLock;
std::vector<uint160> authList;

void add_auth_member(uint160 pubkeyhash)
{
    LOCK(authListLock);
    for (auto& l : authList) {
        if (l == pubkeyhash) {
            return;
        }
    }
    authList.push_back(pubkeyhash);
}

void remove_auth_member(uint160 pubkeyhash)
{
    LOCK(authListLock);
    std::vector<uint160> tempList;
    for (auto& l : authList) {
        if (l != pubkeyhash) {
            tempList.push_back(l);
        }
    }
    authList = tempList;
}

bool is_auth_member(uint160 pubkeyhash)
{
    LOCK(authListLock);
    for (auto& l : authList) {
        if (l == pubkeyhash) {
            return true;
        }
    }
    return false;
}

bool set_auth_user(std::string& privatewif)
{
    CKey key = DecodeSecret(privatewif);
    if (!key.IsValid()) {
        return false;
    }

    CPubKey pubkey = key.GetPubKey();
    uint160 hash160(Hash160(pubkey));
    authUser = hash160;
    authUserKey = privatewif;

    return true;
}

void build_auth_list(const Consensus::Params& params)
{
    LOCK(authListLock);
    if (authList.size() > 0) {
        return;
    }

    authList.push_back(params.initAuthUser);
    authTime = params.initAuthTime;
}

void copy_auth_list(std::vector<uint160>& tempList)
{
    LOCK(authListLock);
    tempList = authList;
}

bool is_signature_valid_raw(std::vector<unsigned char>& signature, uint256& hash)
{
    if (signature.empty()) {
        return false;
    }

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(hash, signature)) {
        return false;
    }

    uint160 hash160(Hash160(pubkey));
    if (!is_auth_member(hash160)) {
        return false;
    }

    return true;
}

bool is_signature_valid_chunk(std::string chunk)
{
    uint256 checkhash;
    std::string signature;
    std::vector<unsigned char> vchsig;

    get_signature_from_auth(chunk, signature);

    vchsig = ParseHex(signature);
    sha256_hash_bin(chunk.c_str(), (char*)&checkhash, (OPAUTH_MAGICLEN*2) + (OPAUTH_OPERATIONLEN*2) + (OPAUTH_TIMELEN*2) + (OPAUTH_HASHLEN*2));

    if (!is_signature_valid_raw(vchsig, checkhash)) {
        return false;
    }

    return true;
}

bool check_contextual_auth(std::string& chunk, int& error_level)
{
    std::string magic, time;

    get_magic_from_auth(chunk, magic);
    if (magic != OPAUTH_MAGIC) {
        error_level = ERR_CHUNKMAGIC;
        return false;
    }

    // set authTime to genesis if not init
    if (authTime == 0) {
        authTime = Params().GetConsensus().initAuthTime;
    }

    get_time_from_auth(chunk, time);
    uint32_t unixtime = hexstring_to_unixtime(time);
    if (unixtime < authTime) {
        // each auth message timestamp must be greater
        // than that of the previous timestamp
        return false;
    }
    authTime = unixtime;

    return true;
}

bool process_auth_chunk(std::string& chunk, int& error_level)
{
    std::string hash, operation;
    get_operation_from_auth(chunk, operation);
    if (operation != OPAUTH_ADDUSER && operation != OPAUTH_DELUSER) {
        return false;
    }

    get_hash_from_auth(chunk, hash);

    if (!is_signature_valid_chunk(chunk)) {
        return false;
    }

    if (operation == OPAUTH_ADDUSER) {
        add_auth_member(uint160S(hash));
    } else if (operation == OPAUTH_DELUSER) {
        remove_auth_member(uint160S(hash));
    } else {
        return false;
    }

    return true;
}

bool is_opreturn_an_authdata(const CScript& script_data, int& error_level)
{
    int type;
    std::string opdata, chunk;
    opdata = HexStr(script_data);
    if (!strip_opreturndata_from_chunk(opdata, chunk)) {
        //LogPrintf("%s - failed at strip_opreturndata_from_chunk\n", __func__);
        return false;
    }

    is_valid_chunk(chunk, type);
    if (type != 2) {
        //LogPrintf("%s - unknown chunk type\n", __func__);
        return false;
    }

    return true;
}

bool found_opreturn_in_authdata(const CScript& script_data, int& error_level, bool test_accept)
{
    int type;
    std::string opdata, chunk;
    opdata = HexStr(script_data);
    if (!strip_opreturndata_from_chunk(opdata, chunk)) {
        //LogPrintf("%s - failed at strip_opreturndata_from_chunk\n", __func__);
        return false;
    }

    is_valid_chunk(chunk, type);
    if (type != 2) {
        //LogPrintf("%s - unknown chunk type\n", __func__);
        return false;
    }

    // used to identify authdata in mempool
    if (test_accept) {
        return true;
    }

    if (!check_contextual_auth(chunk, error_level)) {
        //LogPrintf("%s - failed at check_contextual_auth\n", __func__);
        return false;
    }

    if (!process_auth_chunk(chunk, error_level)) {
        //LogPrintf("%s - failed at process_auth_chunk\n", __func__);
        return false;
    }

    return true;
}

bool does_tx_have_authdata(const CTransaction& tx)
{
    for (unsigned int vout = 0; vout < tx.vout.size(); vout++) {

        const CScript opreturn_out = tx.vout[vout].scriptPubKey;
        if (opreturn_out.IsOpReturn()) {

            int error_level;
            if (!found_opreturn_in_authdata(opreturn_out, error_level, true)) {
                continue;
            } else {
                return true;
            }

        }
    }

    return false;
}

bool check_mempool_for_authdata(const CTxMemPool& mempool)
{
    LOCK(mempool.cs);

    CTxMemPool::txiter it = mempool.mapTx.begin();
    while (it != mempool.mapTx.end()) {
        if (!does_tx_have_authdata(it->GetTx())) {
            continue;
        } else {
            return true;
        }
    }

    return false;
}

bool scan_blocks_for_authdata(ChainstateManager& chainman)
{
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

                const CScript opreturn_out = block.vtx[vtx]->vout[vout].scriptPubKey;
                if (opreturn_out.IsOpReturn()) {
                    int error_level;
                    if (!is_opreturn_an_authdata(opreturn_out, error_level)) {
                        continue;
                    }
                    if (!found_opreturn_in_authdata(opreturn_out, error_level)) {
                        LogPrintf("invalid authdata message in tx %s vout %d\n", block.vtx[vtx]->GetHash().ToString(), vout);
                    } else {
                        LogPrintf("valid authdata message in tx %s vout %d\n", block.vtx[vtx]->GetHash().ToString(), vout);
                    }
                }
            }
        }
    }

    return true;
}

bool generate_auth_payload(std::string& payload, int& type, uint32_t& time, std::string& hash)
{
    payload.clear();

    payload += OPAUTH_MAGIC;
    payload += type == 0 ? OPAUTH_ADDUSER : OPAUTH_DELUSER;
    payload += unixtime_to_hexstring(time);
    payload += hash;

    CKey key = DecodeSecret(authUserKey);
    if (!key.IsValid()) {
        return false;
    }

    uint256 checkhash;
    std::vector<unsigned char> signature;
    sha256_hash_bin(payload.c_str(), (char*)&checkhash, (OPAUTH_MAGICLEN*2) + (OPAUTH_OPERATIONLEN*2) + (OPAUTH_TIMELEN*2) + (OPAUTH_HASHLEN*2));

    if (!key.SignCompact(checkhash, signature)) {
        return false;
    }

    payload += HexStr(signature);

    return true;
}

bool generate_auth_transaction(WalletContext& wallet_context, CMutableTransaction& tx, std::string& opPayload)
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

    // build opreturn
    CTxOut txOpOut = build_opreturn_txout(opPayload);
    tx.vout.push_back(txOpOut);

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
