#include <iomanip>

#include "protocol.h"
#include "util.h"

void get_magic_from_chunk(std::string chunk, std::string& magic) {
    magic = get_hex_from_offset(chunk, 0, OPENCODING_MAGICLEN*2);
}

void get_version_from_chunk(std::string chunk, std::string& version) {
    version = get_hex_from_offset(chunk, OPENCODING_MAGICLEN*2, OPENCODING_VERSIONLEN*2);
}

void get_uuid_from_chunk(std::string chunk, std::string& uuid) {
    uuid = get_hex_from_offset(chunk, (OPENCODING_MAGICLEN*2) + (OPENCODING_VERSIONLEN*2), OPENCODING_UUID*2);
}

void get_chunklen_from_chunk(std::string chunk, std::string& chunklen) {
    chunklen = get_hex_from_offset(chunk, (OPENCODING_MAGICLEN*2) + (OPENCODING_VERSIONLEN*2) + (OPENCODING_UUID*2), OPENCODING_CHUNKLEN*2);
}

void get_signature_from_chunk(std::string chunk, std::string& signature) {
    signature = get_hex_from_offset(chunk, (OPENCODING_MAGICLEN*2) + (OPENCODING_VERSIONLEN*2) + (OPENCODING_UUID*2) + (OPENCODING_CHUNKLEN*2), 0);
}

void get_chunkhash_from_chunk(std::string chunk, std::string& chunkhash) {
    chunkhash = get_hex_from_offset(chunk, (OPENCODING_MAGICLEN*2) + (OPENCODING_VERSIONLEN*2) + (OPENCODING_UUID*2) + (OPENCODING_CHUNKLEN*2), OPENCODING_CHECKSUM*2);
}

void get_chunknum_from_chunk(std::string chunk, std::string& chunknum) {
    chunknum = get_hex_from_offset(chunk, (OPENCODING_MAGICLEN*2) + (OPENCODING_VERSIONLEN*2) + (OPENCODING_UUID*2) + (OPENCODING_CHUNKLEN*2) + (OPENCODING_CHECKSUM*2), OPENCODING_CHUNKNUM*2);
}

void get_chunktotal_from_chunk(std::string chunk, std::string& chunktotal) {
    chunktotal = get_hex_from_offset(chunk, (OPENCODING_MAGICLEN*2) + (OPENCODING_VERSIONLEN*2) + (OPENCODING_UUID*2) + (OPENCODING_CHUNKLEN*2) + (OPENCODING_CHECKSUM*2) + (OPENCODING_CHUNKNUM*2), OPENCODING_CHUNKTOTAL*2);
}

void get_chunkdata_from_chunk(std::string chunk, std::string& chunkdata) {
    int chunkdata_sz;
    std::string chunklen;
    get_chunklen_from_chunk(chunk, chunklen);
    chunkdata_sz = std::stoul(chunklen, nullptr, 16);
    chunkdata = get_hex_from_offset(chunk, (OPENCODING_MAGICLEN*2) + (OPENCODING_VERSIONLEN*2) + (OPENCODING_UUID*2) + (OPENCODING_CHUNKLEN*2) + (OPENCODING_CHECKSUM*2) + (OPENCODING_CHUNKNUM*2) + (OPENCODING_CHUNKTOTAL*2), chunkdata_sz*2);
}

void get_chunkdata_from_chunk(std::string chunk, std::string& chunkdata, int chunkdata_sz) {
    chunkdata = get_hex_from_offset(chunk, (OPENCODING_MAGICLEN*2) + (OPENCODING_VERSIONLEN*2) + (OPENCODING_UUID*2) + (OPENCODING_CHUNKLEN*2) + (OPENCODING_CHECKSUM*2) + (OPENCODING_CHUNKNUM*2) + (OPENCODING_CHUNKTOTAL*2), chunkdata_sz*2);
}
