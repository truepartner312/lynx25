// Copyright (c) 2023 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/manager.h>

bool fStakerRunning{false};
bool fStakerRequestStart{false};
bool fStakerRequestStop{false};

// signal stake thread start
// Bens comment
void stakeman_request_start() {
    fStakerRequestStart = true;
}

// signal stake thread stop
void stakeman_request_stop() {
    fStakerRequestStop = true;
}

// stake thread handler
void *stakeman_handler(wallet::WalletContext& wallet_context, ChainstateManager& chainman, CConnman* connman)
{
    fStakerRequestStart = true;

    while (!ShutdownRequested())
    {
        while (fStakerRunning)
        {
            fStakerRequestStart = false;
            if (fStakerRequestStop)
            {
                StopThreadStakeMiner();
                fStakerRunning = false;
                fStakerRequestStop = false;
                LogPrint(BCLog::POS, "Stopped staking thread\n");
            }
            UninterruptibleSleep(std::chrono::milliseconds{250});
        }

        while (!fStakerRunning)
        {
            fStakerRequestStop = false;
            if (fStakerRequestStart)
            {
                StartThreadStakeMiner(wallet_context, chainman, connman);
                fStakerRunning = true;
                fStakerRequestStart = false;
                LogPrint(BCLog::POS, "Started staking thread\n");
            }
            UninterruptibleSleep(std::chrono::milliseconds{250});
        }

        UninterruptibleSleep(std::chrono::milliseconds{250});
    }

    return (void*)0;
}
