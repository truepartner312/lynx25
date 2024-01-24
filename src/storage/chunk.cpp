#include <opfile/src/util.h>
#include <storage/chunk.h>

void get_magic_from_auth(std::string chunk, std::string& magic) {
    magic = get_hex_from_offset(chunk, 0, OPAUTH_MAGICLEN*2);
}

void get_operation_from_auth(std::string chunk, std::string& operation) {
    operation = get_hex_from_offset(chunk, OPAUTH_MAGICLEN*2, OPAUTH_OPERATIONLEN*2);
}

void get_time_from_auth(std::string chunk, std::string& time) {
    time = get_hex_from_offset(chunk, (OPAUTH_MAGICLEN*2) + (OPAUTH_OPERATIONLEN*2), OPAUTH_TIMELEN*2);
}

void get_hash_from_auth(std::string chunk, std::string& hash) {
    hash = get_hex_from_offset(chunk, (OPAUTH_MAGICLEN*2) + (OPAUTH_OPERATIONLEN*2) + (OPAUTH_TIMELEN*2), OPAUTH_HASHLEN*2);
}

void get_signature_from_auth(std::string chunk, std::string& sig) {
    sig = get_hex_from_offset(chunk, (OPAUTH_MAGICLEN*2) + (OPAUTH_OPERATIONLEN*2) + (OPAUTH_TIMELEN*2) + (OPAUTH_HASHLEN*2), 0);
}
