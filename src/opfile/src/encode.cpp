#include <iomanip>

#include "protocol.h"
#include "util.h"

#include <key_io.h>

extern std::string authUserKey;

bool file_to_hexchunks(std::string filepath, int& protocol, int& error_level, int& total_chunks, std::vector<std::string>& data_chunks) {

    std::string extension;
    if (extract_file_extension(filepath, extension)) {
        // we detected an extension we can store
        protocol = 1;
    }

    int filelen = read_file_size(filepath);
    if (filelen < 0) {
        error_level = ERR_FILESZ;
        return false;
    }

    // an inflated filelen (with extension bytes added)
    int filelenext = filelen;
    filelenext += (protocol == 1 ? OPENCODING_EXTENSION : 0);

    int estchunks = calculate_chunks_from_filesize(filelenext);
    char* buffer = (char*)malloc(filelenext);
    if (!buffer) {
        error_level = ERR_MALLOC;
        free(buffer);
        return false;
    }

    if (!read_file_stream(filepath, buffer, filelen)) {
        error_level = ERR_FILEREAD;
        free(buffer);
        return false;
    }

    // protocol 01 appends 4 byte extension to filestream
    if (protocol == 1) {
        sprintf(buffer+filelen, "%s", extension.c_str());
    }

    int chunk = 0;
    while (chunk * OPENCODING_CHUNKMAX < filelenext) {

        std::stringstream chunk_split;
        for (unsigned int i = (chunk * OPENCODING_CHUNKMAX); i < ((chunk + 1) * OPENCODING_CHUNKMAX); i++) {

            if (i >= filelenext) {
                break;
            }

            unsigned char byte = *(buffer + i);
            chunk_split << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase << (int)byte;
        }

        data_chunks.push_back(chunk_split.str());
        chunk_split.clear();
        chunk++;

        if (debug) {
            printf("\r%d of %d chunks processed (parsing)", chunk, estchunks);
        }
    }

    total_chunks = chunk;
    free(buffer);

    if (debug) printf("\n");

    return true;
}

bool build_chunks_auth_header(std::string header, std::vector<std::string>& encoded_chunks) {

    // we use chunknum 0 to store the authdata, signified by chunklen 0
    std::string authheader = header;
    authheader += "0000";

    char checkhash[OPENCODING_CHECKSUM*8];
    memset(checkhash, 0, sizeof(checkhash));
    sha256_hash_hex(authheader.c_str(), checkhash, authheader.size());
    checkhash[OPENCODING_CHECKSUM*4] = 0;

    CKey key = DecodeSecret(authUserKey);
    if (!key.IsValid()) {
        return false;
    }

    std::vector<unsigned char> signature;
    uint256 authhash = uint256S(std::string(checkhash));
    if (!key.SignCompact(authhash, signature)) {
        return false;
    }

    authheader += HexStr(signature);
    encoded_chunks.push_back(authheader);

    return true;
}

bool build_chunks_with_headers(std::pair<std::string, std::string>& putinfo, int& error_level, int& total_chunks, std::vector<std::string>& encoded_chunks) {

    int protocol;
    bool validcustom;
    std::vector<std::string> data_chunks;
    std::string authheader, header, header2, encoded_chunk, filepath, customuuid;

    filepath = putinfo.first;
    customuuid = putinfo.second;
    validcustom = customuuid.size() == OPENCODING_UUID;

    //! start off using protocol 00, unless we detect an extension
    protocol = 0;

    if (!file_to_hexchunks(filepath, protocol, error_level, total_chunks, data_chunks)) {
        // pass error_level through
        return false;
    }

    header = OPENCODING_MAGIC;
    header += protocol == 1 ? OPENCODING_VERSION[1] : OPENCODING_VERSION[0];
    header += validcustom ? customuuid : generate_uuid(OPENCODING_UUID);

    if (!build_chunks_auth_header(header, encoded_chunks)) {
        return false;
    }

    int chunknum = 1;
    for (auto& data_chunk : data_chunks) {

        int chunklen = data_chunk.size() / 2;
        header2 = get_len_as_hex(chunklen, OPENCODING_CHUNKLEN);

        char checkhash[OPENCODING_CHECKSUM*4];
        memset(checkhash, 0, sizeof(checkhash));
        sha256_hash_hex(data_chunk.c_str(), checkhash, data_chunk.size());
        checkhash[OPENCODING_CHECKSUM*2] = 0;

        header2 += std::string(checkhash);
        header2 += get_len_as_hex(chunknum, OPENCODING_CHUNKNUM);
        header2 += get_len_as_hex(total_chunks, OPENCODING_CHUNKTOTAL);

        encoded_chunk = header + header2 + data_chunk;
        encoded_chunks.push_back(encoded_chunk);

        if (debug) {
            printf("\r%d of %d chunks processed (encoding)", chunknum, total_chunks);
        }

        ++chunknum;
    }

    if (debug) printf("\n");

    return true;
}

