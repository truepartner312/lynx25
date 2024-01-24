#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <vector>

unsigned char binvalue(const char v);
void binlify_from_hex(unsigned char *bin, const char *hex, int len);
void hexlify_from_bin(char *hex, const unsigned char *bin, int len);
int calculate_chunks_from_filesize(int len);
void sha256_hash_bin(const char *input, char *output, unsigned int len);
void sha256_hash_hex(const char *input, char *output, unsigned int len);
int read_file_size(std::string filepath);
bool read_file_stream(std::string filepath, char* buffer, int buflen);
bool write_file_stream(std::string filepath, char* buffer, int buflen);
bool write_partial_stream(FILE* in, char* buffer, int buflen);
std::string get_len_as_hex(int len, int padding);
std::string get_hex_from_offset(std::string hexstring, int offset, int len);
std::string generate_uuid(int len);
bool generate_random_binary(std::string filepath, int len);
bool compare_two_binary_files(std::string filepath1, std::string filepath2);
int64_t current_timestamp();
std::string strip_trailing_slash(std::string& input);
bool extract_file_extension(std::string& filepath, std::string& extension);

#endif // UTIL_H
