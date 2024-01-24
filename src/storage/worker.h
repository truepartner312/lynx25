// Copyright (c) 2023 Lynx Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STORAGE_WORKER_H
#define BITCOIN_STORAGE_WORKER_H

enum {
    WORKER_IDLE,
    WORKER_BUSY,
    WORKER_ERROR
};

void thread_storage_worker();

void add_result_entry();
std::string get_result_hash();
void add_result_text(std::string& result);

void add_put_task(std::string put_info, std::string put_uuid = "");
void add_get_task(std::pair<std::string, std::string> get_info);
void get_storage_worker_status(int& status);

#endif // BITCOIN_STORAGE_WORKER_H
