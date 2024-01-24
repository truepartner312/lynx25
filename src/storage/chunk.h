// Copyright (c) 2023 Lynx Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STORAGE_CHUNK_H
#define BITCOIN_STORAGE_CHUNK_H

#include <validation.h>

// #opauth
// barrystyle 02072023
//
// offset 0-3     |   magic bytes 'lynk' (4b)
// offset 4       |   operation byte (1b)
// offset 5-8     |   unixtime of command (4b)
// offset 9-28    |   hash160 of operand (20b)
// offset 29-     |   signed dblsha of above

//! byte sizes for encoding/decoding
const int OPAUTH_MAGICLEN = 4;
const int OPAUTH_OPERATIONLEN = 1;
const int OPAUTH_TIMELEN = 4;
const int OPAUTH_HASHLEN = 20;
const int OPAUTH_SIGHASHLEN = 32;

//! const bytearray present in file
const std::string OPAUTH_ADDUSER = "00";
const std::string OPAUTH_DELUSER = "01";
const std::string OPAUTH_MAGIC = "6c796e6b";

void get_magic_from_auth(std::string chunk, std::string& magic);
void get_operation_from_auth(std::string chunk, std::string& operation);
void get_time_from_auth(std::string chunk, std::string& time);
void get_hash_from_auth(std::string chunk, std::string& hash);
void get_signature_from_auth(std::string chunk, std::string& sig);

#endif // BITCOIN_STORAGE_CHUNK_H
