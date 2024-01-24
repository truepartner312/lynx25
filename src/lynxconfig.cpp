#include <chainparams.h>
#include <opfile/src/util.h>
#include <storage/util.h>
#include <util/system.h>

#include <fstream>
#include <iostream>

void write_lynx_config(std::string& configpath, std::string password, bool testnet)
{
    std::ofstream config(configpath);
    config << "listen=1" << std::endl;
    config << "server=1" << std::endl;
    config << "daemon=1" << std::endl;
    if (testnet)
        config << "testnet=1" << std::endl;
    config << "rpcuser=testuser" << std::endl;
    config << "rpcpassword=" << password << std::endl;
    config << "[main]" << std::endl;
    config << "rpcbind=127.0.0.1" << std::endl;
    config << "rpcallowip=127.0.0.1" << std::endl;
    config << "[test]" << std::endl;
    config << "rpcbind=127.0.0.1" << std::endl;
    config << "rpcallowip=127.0.0.1" << std::endl;
    config.close();
}

void check_lynx_config(const ArgsManager& args)
{
    fs::path config_file_path = args.GetConfigFilePath();
    std::string configpath = fs::PathToString(config_file_path);
    bool testnet = Params().NetworkIDString() == CBaseChainParams::TESTNET;

    if (!does_file_exist(configpath)) {
        std::string password = generate_uuid(16);
        write_lynx_config(configpath, password, testnet);
    }
}
