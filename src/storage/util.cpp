// Copyright (c) 2023 Lynx Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <opfile/src/protocol.h>
#include <opfile/src/util.h>
#include <rpc/register.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <storage/chunk.h>
#include <storage/storage.h>
#include <storage/worker.h>
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

#include <filesystem>

using namespace wallet;

WalletContext* storage_context = nullptr;
ChainstateManager* storage_chainman = nullptr;

void set_wallet_context(WalletContext* wallet_context)
{
    storage_context = wallet_context;
}

void set_chainman_context(ChainstateManager& chainman_context)
{
    storage_chainman = &chainman_context;
}

bool strip_opreturndata_from_chunk(std::string& opdata, std::string& chunk)
{
    chunk.clear();
    std::stringstream push_data;
    push_data << opdata.at(2) << opdata.at(3);
    // OP_PUSHDATA1 (80-255)
    if (push_data.str() == "4d") {
        for (int i=8; i<opdata.size(); i++) {
            chunk = chunk + opdata[i];
        }
        return true;
    }
    // OP_PUSHDATA2 (256-65535)
    if (push_data.str() == "4c") {
        for (int i=6; i<opdata.size(); i++) {
            chunk = chunk + opdata[i];
        }
        return true;
    }
    // legacy encoding (0-79?)
    for (int i=4; i<opdata.size(); i++) {
        chunk = chunk + opdata[i];
    }
    return true;
}

CTxOut build_opreturn_txout(std::string& payload)
{
    CScript scriptOp;
    scriptOp << OP_RETURN << ParseHex(payload);
    CTxOut opreturn_out(0, scriptOp);
    return opreturn_out;
}

void is_valid_chunk(std::string& chunk, int& type)
{
    type = 0; // unknown/invalid
    std::stringstream push_data;
    push_data << chunk.at(0) << chunk.at(1)
              << chunk.at(2) << chunk.at(3)
              << chunk.at(4) << chunk.at(5)
              << chunk.at(6) << chunk.at(7);
    if (push_data.str() == OPENCODING_MAGIC) {
        type = 1; // data chunk
    } else if (push_data.str() == OPAUTH_MAGIC) {
        type = 2; // auth chunk
    }
}

std::string unixtime_to_hexstring(uint32_t& time)
{
    char chrtime[16];
    memset(chrtime, 0, sizeof(chrtime));
    sprintf(chrtime, "%08x", time);
    return std::string(chrtime);
}

uint32_t hexstring_to_unixtime(std::string& time)
{
    uint32_t numtime;
    numtime = std::stoul(time, nullptr, 16);
    return numtime;
}

bool does_path_exist(std::string& path)
{
    return std::filesystem::is_directory(path);
}

bool does_file_exist(std::string& filepath)
{
    return std::filesystem::exists(filepath);
}

void strip_unknown_chars(std::string& input)
{
    std::string cleaned;
    for (unsigned int i=0; i<input.size(); i++) {
        char a = input[i];
        if ((a >= 97 && a <= 122) || (a >= 48 && a <= 57)) {
            cleaned += input[i];
        }
    }
    input = cleaned;
}

static bool is_hex_notation(std::string const& s)
{
    return s.size() > 2
      && s.find_first_not_of("0123456789abcdef", 2) == std::string::npos;
}

bool is_valid_uuid(std::string& uuid)
{
    if (uuid.size() != OPENCODING_UUID) return false;
    if (!is_hex_notation(uuid)) return false;
    return true;
}
