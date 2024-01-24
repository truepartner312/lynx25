#include "chunk.h"
#include "protocol.h"
#include "util.h"

#include <storage/auth.h>

#include <key_io.h>

bool check_chunk_contextual(std::string chunk, int& protocol, int& error_level)
{
    bool valid;
    std::string magic, version;

    // check lynx magic
    get_magic_from_chunk(chunk, magic);
    if (magic != OPENCODING_MAGIC) {
        error_level = ERR_CHUNKMAGIC;
        return false;
    }

    // check version byte
    valid = false;
    get_version_from_chunk(chunk, version);
    for (auto& l : OPENCODING_VERSION) {
        if (version == l) {
            valid = true;
        }
    }

    // bail on unknown protocol types
    if (!valid) {
        error_level = ERR_CHUNKVERSION;
        return false;
    }

    // pass protocol back
    protocol = std::stoul(version, nullptr, 16);

    return true;
}

bool is_valid_authchunk(std::string& chunk, int& error_level)
{
    // extract signature
    std::string signature;
    std::vector<unsigned char> vchsig;
    get_signature_from_chunk(chunk, signature);
    vchsig = ParseHex(signature);

    // calculate hash
    char checkhash[OPENCODING_CHECKSUM*8];
    memset(checkhash, 0, sizeof(checkhash));
    sha256_hash_hex(chunk.c_str(), checkhash, (OPENCODING_MAGICLEN*2) + (OPENCODING_VERSIONLEN*2) + (OPENCODING_UUID*2) + (OPENCODING_CHUNKLEN*2));
    checkhash[OPENCODING_CHECKSUM*4] = 0;
    uint256 authhash = uint256S(std::string(checkhash));

    // extract pubkey
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(authhash, vchsig)) {
        error_level = ERR_CHUNKAUTHSIG;
        return false;
    }

    // test pubkey
    uint160 hash160(Hash160(pubkey));
    if (!is_auth_member(hash160)) {
        error_level = ERR_CHUNKAUTHUNK;
        return false;
    }

    return true;
}

bool build_file_from_chunks(std::pair<std::string, std::string> get_info, int& error_level, int& total_chunks, std::vector<std::string>& encoded_chunks) {

    error_level = NO_ERROR;

    bool lastchunk;
    char checkhash[OPENCODING_CHECKSUM*4];
    unsigned char buffer[OPENCODING_CHUNKMAX*2];
    int protocol, offset, thischunk, chunknum2, chunklen2, chunktotal2, extskip;
    std::string chunklen, uuid, uuid2, chunkhash, checksum, chunknum, chunktotal, chunkdata, filepath;

    offset = 0;
    extskip = 0;
    protocol = 0;
    thischunk = 1;
    lastchunk = false;
    filepath = strip_trailing_slash(get_info.second) + "/" + get_info.first;

    FILE* in = fopen(filepath.c_str(), "wb");
    if (!in) {
        error_level = ERR_FILEOPEN;
        return false;
    }

    for (auto& chunk : encoded_chunks) {

        // note the last chunk
        if (chunk == encoded_chunks.back()) {
            lastchunk = true;
        }

        // perform contextual checks
        if (!check_chunk_contextual(chunk, protocol, error_level)) {
            //pass error_level back
            return false;
        }

        // ensure uuid is uniform
        get_uuid_from_chunk(chunk, uuid);
        if (uuid2.size() > 0) {
            if (uuid != uuid2) {
                error_level = ERR_CHUNKUUID;
                return false;
            }
        } else {
            uuid2 = uuid;
        }

        // ensure chunklen is uniform (besides last chunk)
        get_chunklen_from_chunk(chunk, chunklen);
        chunklen2 = std::stoul(chunklen, nullptr, 16);

        if (chunklen2 == 0) {
            continue;
        }

        // ... if datachunk
        if (lastchunk == false && (chunklen2 != OPENCODING_CHUNKMAX)) {
            error_level = ERR_CHUNKLEN;
            return false;
        }

        // test chunkdata hash to calculated chunkdata hash
        get_chunkhash_from_chunk(chunk, chunkhash);
        get_chunkdata_from_chunk(chunk, chunkdata, chunklen2);
        sha256_hash_hex(chunkdata.c_str(), checkhash, chunklen2*2);
        checkhash[OPENCODING_CHECKSUM*2] = 0;
        if (chunkhash != std::string(checkhash)) {
            error_level = ERR_CHUNKHASH;
            return false;
        }

        // check chunknum is uniform
        get_chunknum_from_chunk(chunk, chunknum);
        chunknum2 = std::stoul(chunknum, nullptr, 16);
        if (thischunk != chunknum2) {
            error_level = ERR_CHUNKNUM;
            return false;
        }

        // check chunktotal is correct
        get_chunktotal_from_chunk(chunk, chunktotal);
        chunktotal2 = std::stoul(chunktotal, nullptr, 16);
        if (encoded_chunks.size() != chunktotal2) {
            error_level = ERR_CHUNKTOTAL;
            return false;
        }

        // if protocol is 01 and lastchunk is true (extensiondata)
        if (lastchunk == true && protocol == 1) {
            extskip = OPENCODING_EXTENSION;
        }

        // write to buffer
        binlify_from_hex(&buffer[0], chunkdata.c_str(), chunkdata.size());
        if (!write_partial_stream(in, (char*)buffer, (chunkdata.size() / 2) - extskip)) {
            error_level = ERR_FILEWRITE;
            return false;
        }

        if (debug) {
            printf("\r%d of %d chunks processed (decoding)", thischunk, chunktotal2);
        }

        ++thischunk;
    }

    fclose(in);

    //! if protocol 01, rename file with extension
    if (protocol == 1) {

        std::string extension;
        int extoffset = (chunkdata.size() / 2) - extskip;
        for (int extwrite = extoffset; extwrite < extoffset + OPENCODING_EXTENSION; extwrite++) {
            extension += buffer[extwrite];
        }

        std::string newfilepath = filepath + "." + extension;

        if (std::rename(filepath.c_str(), newfilepath.c_str())) {
            error_level = ERR_EXTENSION;
            return false;
        }
    }

    if (debug) printf("\n");

    return true;
}
