#ifndef CHUNK_H
#define CHUNK_H

#include <string>
#include <vector>

void get_magic_from_chunk(std::string chunk, std::string& magic);
void get_version_from_chunk(std::string chunk, std::string& version);
void get_uuid_from_chunk(std::string chunk, std::string& uuid);
void get_chunklen_from_chunk(std::string chunk, std::string& chunklen);
void get_signature_from_chunk(std::string chunk, std::string& signature);
void get_chunkhash_from_chunk(std::string chunk, std::string& chunkhash);
void get_chunknum_from_chunk(std::string chunk, std::string& chunknum);
void get_chunktotal_from_chunk(std::string chunk, std::string& chunktotal);
void get_chunkdata_from_chunk(std::string chunk, std::string& chunkdata);
void get_chunkdata_from_chunk(std::string chunk, std::string& chunkdata, int chunkdata_sz);

#endif // CHUNK_H
