// Copyright (c) 2023 Lynx Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <opfile/src/decode.h>
#include <opfile/src/encode.h>
#include <opfile/src/protocol.h>
#include <opfile/src/util.h>
#include <storage/storage.h>
#include <storage/worker.h>

int workerStatus;
RecursiveMutex workQueueLock, workResultLock;

std::vector<std::pair<std::string, std::string>> workQueuePut;
std::vector<std::pair<std::string, std::string>> workQueueGet;
std::vector<std::pair<std::string, std::string>> workQueueResult;

extern ChainstateManager* storage_chainman;
extern wallet::WalletContext* storage_context;

void add_put_task(std::string put_info, std::string put_uuid)
{
    LOCK(workQueueLock);
    add_result_entry();
    workQueuePut.push_back(std::make_pair(put_info, put_uuid));
}

void add_get_task(std::pair<std::string, std::string> get_info)
{
    LOCK(workQueueLock);
    add_result_entry();
    workQueueGet.push_back(get_info);
}

void add_result_entry()
{
    LOCK(workResultLock);
    workQueueResult.push_back(std::pair(generate_uuid(8), std::string("")));
}

std::string get_result_hash()
{
    LOCK(workResultLock);
    return workQueueResult.back().first;
}

void add_result_text(std::string& result)
{
    LOCK(workResultLock);
    workQueueResult.back().second = result;
}

void get_storage_worker_status(int& status)
{
    LOCK(workQueueLock);
    status = workerStatus;
}

void set_storage_worker_status(int status)
{
    LOCK(workQueueLock);
    workerStatus = status;
}

void perform_put_task(std::pair<std::string, std::string>& put_info, int& error_level)
{
    // get wallet handle
    auto vpwallets = GetWallets(*storage_context);
    size_t nWallets = vpwallets.size();
    if (nWallets < 1) {
        error_level = ERR_NOWALLET;
        return;
    }

    // see if there are enough inputs
    int usable_inputs;
    int filelen = read_file_size(put_info.first);
    int est_chunks = calculate_chunks_from_filesize(filelen);
    estimate_coins_for_opreturn(vpwallets.front().get(), usable_inputs);
    if (usable_inputs < est_chunks) {
        error_level = ERR_LOWINPUTS;
        return;
    }

    // build chunks from file
    int total_chunks;
    std::vector<std::string> encoded_chunks;
    if (!build_chunks_with_headers(put_info, error_level, total_chunks, encoded_chunks)) {
        //pass error_level back
        return;
    }

    // create tx, sign and submit for each chunk
    CMutableTransaction txChunk;
    std::vector<std::string> batch_chunks;
    if (encoded_chunks.size() <= OPRETURN_PER_TX) {
        batch_chunks = encoded_chunks;
        if (!generate_selfsend_transaction(*storage_context, txChunk, batch_chunks)) {
            error_level = ERR_TXGENERATE;
            return;
        }
        return;
    } else {
        for (auto &l : encoded_chunks) {
             batch_chunks.push_back(l);
             if (batch_chunks.size() == OPRETURN_PER_TX) {
                 if (!generate_selfsend_transaction(*storage_context, txChunk, batch_chunks)) {
                     error_level = ERR_TXGENERATE;
                     return;
                 }
                 batch_chunks.clear();
                 txChunk = CMutableTransaction();
             }
        }
        txChunk = CMutableTransaction();
        if (!generate_selfsend_transaction(*storage_context, txChunk, batch_chunks)) {
            error_level = ERR_TXGENERATE;
            return;
        }
        batch_chunks.clear();
    }
}

void perform_get_task(std::pair<std::string, std::string> get_info, int& error_level)
{
    std::vector<std::string> chunks;
    if (!scan_blocks_for_specific_uuid(*storage_chainman, get_info.first, error_level, chunks)) {
        //pass error_level back
        return;
    }

    int total_chunks = chunks.size();
    if (!build_file_from_chunks(get_info, error_level, total_chunks, chunks)) {
        //pass error_level back
        return;
    }
}

void thread_storage_worker()
{
    int error_level;
    set_storage_worker_status(WORKER_IDLE);

    while (!ShutdownRequested()) {

        UninterruptibleSleep(500ms);

        // check queues under lock
        int putqueue_sz, getqueue_sz;
        {
            LOCK(workQueueLock);
            putqueue_sz = workQueuePut.size();
            getqueue_sz = workQueueGet.size();
        }

        // buffer for sprintf result
        char buffer[128];
        memset(buffer, 0, sizeof(buffer));

        // perform putqueue tasks
        if (putqueue_sz > 0) {
            std::pair<std::string, std::string> putTask;
            error_level = NO_ERROR;
            set_storage_worker_status(WORKER_BUSY);
            {
                LOCK(workQueueLock);
                putTask = workQueuePut.back();
            }
            perform_put_task(putTask, error_level);
            if (error_level != NO_ERROR) {
                sprintf(buffer, "putTask %s had error_level %d", putTask.first.c_str(), error_level);
                std::string stringbuf = std::string(buffer);
                add_result_text(stringbuf);
            } else {
                sprintf(buffer, "putTask %s completed successfully", putTask.first.c_str());
                std::string stringbuf = std::string(buffer);
                add_result_text(stringbuf);
            }
            {
                LOCK(workQueueLock);
                workQueuePut.pop_back();
            }
            set_storage_worker_status(WORKER_IDLE);
        }

        // perform getqueue tasks
        if (getqueue_sz > 0) {
            std::pair<std::string, std::string> getTask;
            error_level = NO_ERROR;
            set_storage_worker_status(WORKER_BUSY);
            {
                LOCK(workQueueLock);
                getTask = workQueueGet.back();
            }
            perform_get_task(getTask, error_level);
            if (error_level != NO_ERROR) {
                sprintf(buffer, "getTask %s, %s had error_level %d", getTask.first.c_str(), getTask.second.c_str(), error_level);
                std::string stringbuf = std::string(buffer);
                add_result_text(stringbuf);
            } else {
                sprintf(buffer, "getTask %s, %s completed successfully", getTask.first.c_str(), getTask.second.c_str());
                std::string stringbuf = std::string(buffer);
                add_result_text(stringbuf);
            }
            {
                LOCK(workQueueLock);
                workQueueGet.pop_back();
            }
            set_storage_worker_status(WORKER_IDLE);
        }

        if (ShutdownRequested()) {
            return;
        }
    }
}
