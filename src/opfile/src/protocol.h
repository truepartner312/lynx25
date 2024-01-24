#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <vector>

const bool debug = false;

//! max limits for encoding/decoding
const int OPRETURN_PER_TX = 256;

//! byte sizes for encoding/decoding
const int OPENCODING_CHUNKMAX = 512;
const int OPENCODING_MAGICLEN = 4;
const int OPENCODING_VERSIONLEN = 1;
const int OPENCODING_UUID = 16;
const int OPENCODING_CHUNKLEN = 2;
const int OPENCODING_CHECKSUM = 16;
const int OPENCODING_CHUNKNUM = 4;
const int OPENCODING_CHUNKTOTAL = 4;
const int OPENCODING_EXTENSION = 4;

//! const bytearray present in file
const std::vector<std::string> OPENCODING_VERSION = { "00", "01" };
const std::string OPENCODING_MAGIC = "6c796e78";

//! variations of OPENCODING_VERSION
//!
//! 00 is standard base with authchunks
//! 01 is a variation where 4 extra bytes are added to the datachunk (file extension in ascii)

//! errorlevel enum
enum {
     NO_ERROR = 0,
     //internal
     ERR_FILESZ,
     ERR_MALLOC,
     //encoding
     ERR_CHUNKMAGIC,
     ERR_CHUNKVERSION,
     ERR_CHUNKUUID,
     ERR_CHUNKLEN,
     ERR_CHUNKHASH,
     ERR_CHUNKNUM,
     ERR_CHUNKTOTAL,
     ERR_CHUNKFAIL,
     //fileop
     ERR_FILEOPEN,
     ERR_FILEREAD,
     ERR_FILEWRITE,
     //wallet
     ERR_NOWALLET,
     ERR_LOWINPUTS,
     ERR_TXGENERATE,
     //auth
     ERR_CHUNKAUTHNONE,
     ERR_CHUNKAUTHSIG,
     ERR_CHUNKAUTHUNK,
     //feature
     ERR_EXTENSION,
};

#endif // PROTOCOL_H
