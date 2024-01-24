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
#include <storage/auth.h>
#include <storage/chunk.h>
#include <storage/storage.h>
#include <storage/util.h>
#include <storage/worker.h>
#include <sync.h>
#include <timedata.h>
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

using namespace wallet;
using node::ReadBlockFromDisk;

extern uint160 authUser;
extern WalletContext* storage_context;
extern ChainstateManager* storage_chainman;
extern std::vector<std::pair<std::string, std::string>> workQueueResult;

static RPCHelpMan putfile()
{
    return RPCHelpMan{"putfile",
        "\nStore a file in the Lynx blockchain.\n",
         {
             {"filepath", RPCArg::Type::STR, RPCArg::Optional::NO, "Filename with full path."},
             {"uuid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "UUID overwrite (optional)."},
         },
         RPCResult{
            RPCResult::Type::STR, "", "success or failure"},
         RPCExamples{
            "\nStore /tmp/file.bin on the blockchain.\n"
            + HelpExampleCli("putfile", "/tmp/file.bin")
        + HelpExampleRpc("putfile", "/tmp/file.bin")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!is_auth_member(authUser)) {
        return std::string("not-authenticated");
    }

    std::string put_filename = request.params[0].get_str();
    std::string put_uuid = request.params[1].get_str();
    if (is_valid_uuid(put_uuid)) {
        std::vector<std::string> uuid_found;
        scan_blocks_for_uuids(*storage_chainman, uuid_found);
        for (auto& uuid : uuid_found) {
             if (uuid == put_uuid)
                 return std::string("uuid-exists");
        }
    } else {
        put_uuid = "";
    }

    if (read_file_size(put_filename) > 0) {
        add_put_task(put_filename, put_uuid);
        return get_result_hash();
    }

    return std::string("failure");
},
    };
}

static RPCHelpMan getfile()
{
    return RPCHelpMan{"getfile",
        "\nRetrieve a file from the Lynx blockchain.\n",
         {
             {"uuid", RPCArg::Type::STR, RPCArg::Optional::NO, "UUID of file."},
             {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "Path to save file."},
         },
         RPCResult{
            RPCResult::Type::STR, "", "success or failure"},
         RPCExamples{
            "\nRetrieve UUID 00112233445566778899aabbccddeeff and store in /tmp.\n"
            + HelpExampleCli("getfile", "00112233445566778899aabbccddeeff /tmp")
        + HelpExampleRpc("getfile", "00112233445566778899aabbccddeeff /tmp")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string uuid = request.params[0].get_str();
    std::string path = request.params[1].get_str();
    if (!does_path_exist(path)) {
        return std::string("invalid-path");
    }
    if (uuid.size() == OPENCODING_UUID*2) {
        add_get_task(std::make_pair(uuid, path));
        return get_result_hash();
    }

    return NullUniValue;
},
    };
}

static RPCHelpMan getuuids()
{
    return RPCHelpMan{"getuuids",
                "\nScan the chain for storage UUIDs.\n",
                {},
                {
                    RPCResult{
                        RPCResult::Type::ARR, "", "",
                        {{RPCResult::Type::STR_HEX, "", "The uuid's of the stored file."}}},
                },
                RPCExamples{
                    HelpExampleCli("getuuids", "")
            + HelpExampleRpc("getuuids", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VARR);

    std::vector<std::string> uuid_found;
    scan_blocks_for_uuids(*storage_chainman, uuid_found);
    for (auto& uuid : uuid_found) {
        ret.push_back(uuid);
    }

    return ret;
},
    };
}

static RPCHelpMan getstatus()
{
    return RPCHelpMan{"getstatus",
                "\nReturn the recent job and worker status.\n",
                {},
                {
                    RPCResult{
                        RPCResult::Type::ARR, "", "",
                            {{RPCResult::Type::STR, "", "Worker and job status information."}}
                    },
                },
                RPCExamples{
                    HelpExampleCli("getstatus", "")
            + HelpExampleRpc("getstatus", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VARR);

    // worker
    int status;
    get_storage_worker_status(status);
    if (status == WORKER_IDLE) {
        ret.push_back(std::string("WORKER_IDLE"));
    } else if (status == WORKER_BUSY) {
        ret.push_back(std::string("WORKER_BUSY"));
    } else {
        ret.push_back(std::string("WORKER_ERROR"));
    }

    // job list
    int total_jobs = workQueueResult.size();
    int start_jobs = total_jobs - 15;
    if (start_jobs < 0) start_jobs = 0;
    for (int i=start_jobs; i<total_jobs; i++) {
        std::string job_result = workQueueResult[i].first + ", " + workQueueResult[i].second;
        ret.push_back(job_result);
    }

    return ret;
},
    };
}

static RPCHelpMan listauth()
{
    return RPCHelpMan{"listauth",
                "\nDisplay the users present in the authlist (the user's hash160).\n",
                {},
                {
                    RPCResult{
                        RPCResult::Type::ARR, "", "",
                        {{RPCResult::Type::STR_HEX, "", "The hash160 of the users authentication key."}}},
                },
                RPCExamples{
                    HelpExampleCli("listauth", "")
            + HelpExampleRpc("listauth", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VARR);

    std::vector<uint160> tempList;
    copy_auth_list(tempList);
    for (auto& l : tempList) {
        ret.push_back(l.ToString());
    }

    return ret;
},
    };
}

static RPCHelpMan setauth()
{
    return RPCHelpMan{"setauth",
                "\nSet the default authuser to the given details.\n",
                {
                    {"privatekey", RPCArg::Type::STR, RPCArg::Optional::NO, "WIF-Format Privatekey."},
                },
                {
                    RPCResult{
                        RPCResult::Type::ARR, "", "",
                        {{RPCResult::Type::STR, "", "The status of the operation."}}},
                },
                RPCExamples{
                    HelpExampleCli("setauth", "cVDy3BpQNFpGVnsrmXTgGSuU3eq5aeyo513hJazyCEj9s6eDiFj8")
            + HelpExampleRpc("setauth", "cVDy3BpQNFpGVnsrmXTgGSuU3eq5aeyo513hJazyCEj9s6eDiFj8")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VARR);

    std::string privatewif = request.params[0].get_str();
    if (privatewif.empty() || !set_auth_user(privatewif)) {
        ret.push_back(std::string("failure"));
    } else {
        if (!is_auth_member(authUser)) {
            ret.push_back(std::string("failure"));
        } else {
            ret.push_back(std::string("success"));
        }
    }

    return ret;
},
    };
}

static RPCHelpMan addauth()
{
    return RPCHelpMan{"addauth",
                "\nAdd an authuser to the authlist.\n",
                {
                    {"hash160", RPCArg::Type::STR, RPCArg::Optional::NO, "The hash160 of the users key."},
                },
                RPCResult{
                    RPCResult::Type::STR, "", "success or failure"},
                RPCExamples{
                    HelpExampleCli("addauth", "00112233445566778899aabbccddeeff00112233")
            + HelpExampleRpc("addauth", "00112233445566778899aabbccddeeff00112233")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const CTxMemPool& mempool = EnsureAnyMemPool(request.context);
    if (check_mempool_for_authdata(mempool)) {
        return std::string("authtx-in-mempool");
    }

    std::string hash160 = request.params[0].get_str();
    if (hash160.size() != OPAUTH_HASHLEN*2) {
        return std::string("hash160-wrong-size");
    }
    uint160 hash = uint160S(hash160);

    // are we authenticated
    if (is_auth_member(authUser)) {

        int type;
        uint32_t time;
        CMutableTransaction tx;
        std::string opreturn_payload;

        type = 0;
        time = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());

        if (!generate_auth_payload(opreturn_payload, type, time, hash160)) {
            return std::string("error-generating-authpayload");
        }

        if (!generate_auth_transaction(*storage_context, tx, opreturn_payload)) {
            return std::string("error-generating-authtransaction");
        }

        return std::string("success");

    } else {
        return std::string("failure");
    }

    return std::string("failure");
},
    };
}

static RPCHelpMan delauth()
{
    return RPCHelpMan{"delauth",
                "\nDelete an authuser from the authlist.\n",
                {
                    {"hash160", RPCArg::Type::STR, RPCArg::Optional::NO, "The hash160 of the users key."},
                },
                RPCResult{
                    RPCResult::Type::STR, "", "success or failure"},
                RPCExamples{
                    HelpExampleCli("delauth", "00112233445566778899aabbccddeeff00112233")
            + HelpExampleRpc("delauth", "00112233445566778899aabbccddeeff00112233")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const CTxMemPool& mempool = EnsureAnyMemPool(request.context);
    if (check_mempool_for_authdata(mempool)) {
        return std::string("authtx-in-mempool");
    }

    std::string hash160 = request.params[0].get_str();
    if (hash160.size() != OPAUTH_HASHLEN*2) {
        return std::string("hash160-wrong-size");
    }
    uint160 hash = uint160S(hash160);

    // are we authenticated
    if (is_auth_member(authUser)) {

        int type;
        uint32_t time;
        CMutableTransaction tx;
        std::string opreturn_payload;

        type = 1;
        time = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());

        if (!generate_auth_payload(opreturn_payload, type, time, hash160)) {
            return std::string("error-generating-authpayload");
        }

        if (!generate_auth_transaction(*storage_context, tx, opreturn_payload)) {
            return std::string("error-generating-authtransaction");
        }

        return std::string("success");

    } else {
        return std::string("failure");
    }

    return std::string("failure");
},
    };
}

void RegisterStorageRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"lynx", &putfile},
        {"lynx", &getfile},
        {"lynx", &getuuids},
        {"lynx", &getstatus},
        {"lynx", &listauth},
        {"lynx", &setauth},
        {"lynx", &addauth},
        {"lynx", &delauth},
    };

    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
