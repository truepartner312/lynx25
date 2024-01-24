#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <string.h>

#include "protocol.h"

#include <openssl/sha.h>

unsigned char binvalue(const char v) {
    if (v >= '0' && v <= '9') {
        return v-'0';
    }
    if (v >= 'a' && v <= 'f') {
        return v-'a'+10;
    }
    return 0;
}

void binlify_from_hex(unsigned char *bin, const char *hex, int len) {
    for (int i=0; i<len/2; i++) {
        bin[i] = binvalue(hex[i*2])<<4 | binvalue(hex[i*2+1]);
    }
}

void hexlify_from_bin(char *hex, const unsigned char *bin, int len) {
    hex[0] = 0;
    for(int i=0; i < len; i++) {
        sprintf(hex+strlen(hex), "%02x", bin[i]);
    }
}

int calculate_chunks_from_filesize(int len) {
    int chunks = 1;
    while ((len -= OPENCODING_CHUNKMAX) > 0) {
        chunks += 1;
    }
    return chunks;
}

void sha256_hash_bin(const char *input, char *output, unsigned int len) {
    SHA256((const unsigned char*)input, len, (unsigned char*)output);
}

void sha256_hash_hex(const char *input, char *output, unsigned int len) {
    char output1[32];
    SHA256((const unsigned char*)input, len, (unsigned char*)output1);
    hexlify_from_bin(output, (unsigned char *)output1, 32);
}

int read_file_size(std::string filepath) {
    std::filesystem::path in {filepath.c_str()};
    return std::filesystem::file_size(in);
}

bool read_file_stream(std::string filepath, char* buffer, int buflen) {
    FILE* in = fopen(filepath.c_str(), "rb");
    if (!in)
        return false;
    fread(buffer, 1, buflen, in);
    fclose(in);
    return true;
}

bool write_file_stream(std::string filepath, char* buffer, int buflen) {
    FILE* in = fopen(filepath.c_str(), "wb");
    if (!in)
        return false;
    fwrite(buffer, 1, buflen, in);
    fclose(in);
    return true;
}

bool write_partial_stream(FILE* in, char* buffer, int buflen) {
    if (!in)
        return false;
    fwrite(buffer, 1, buflen, in);
    return true;
}

std::string get_len_as_hex(int len, int padding) {
    std::stringstream hexstream;
    hexstream << std::hex << len;
    auto hex = hexstream.str();
    while (hex.length() < (padding * 2)) {
        hex = "0" + hex;
    }
    hex.resize(padding * 2);
    return hex;
}

std::string get_hex_from_offset(std::string hexstring, int offset, int len) {
    std::string hexstream;
    for (int i = offset; i < (len > 0 ? offset + len : hexstring.size()); i++) {
        hexstream = hexstream + hexstring[i];
    }
    return hexstream;
}

static unsigned int random_char() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    return dis(gen);
}

static std::string generate_hex(const unsigned int len) {
    std::stringstream ss;
    for (auto i = 0; i < len; i++) {
        const auto rc = random_char();
        std::stringstream hexstream;
        hexstream << std::hex << rc;
        auto hex = hexstream.str();
        ss << (hex.length() < 2 ? '0' + hex : hex);
    }
    return ss.str();
}

std::string generate_uuid(int len) {
    std::stringstream hexstream;
    hexstream << generate_hex(len);
    return hexstream.str();
}

bool generate_random_binary(std::string filepath, int len) {
    char *ptr = (char*)malloc(len);
    for (int i = 0; i < len; i++) {
        *(ptr + i) = rand();
    }
    if (!write_file_stream(filepath, ptr, len)) {
        free(ptr);
        return false;
    }
    free(ptr);
    return true;
}

bool compare_two_binary_files(std::string filepath1, std::string filepath2) {
    FILE *fp1, *fp2;
    int n1, n2, offset;
    char tmp1[4096], tmp2[4096];
    offset = 0;
    fp1 = fopen(filepath1.c_str(), "rb");
    fp2 = fopen(filepath2.c_str(), "rb");
    do {
        n1 = fread(tmp1, sizeof *tmp1, sizeof tmp1 / sizeof *tmp1, fp1);
        if (n1 == 0 && ferror(fp1)) return false;
        n2 = fread(tmp2, sizeof *tmp2, sizeof tmp2 / sizeof *tmp2, fp2);
        if (n2 == 0 && ferror(fp2)) return false;
        int n_min = n1 < n2 ? n1 : n2;
        if (memcmp(tmp1, tmp2, n_min)) {
            for (int i = 0; i < n_min; i++) {
                if (tmp1[i] != tmp2[i]) {
                    offset += i;
                    return false;
                }
            }
        }
        offset += n_min;
        if (n1 > n_min) return false;
        if (n2 > n_min) return false;
    } while (n1);
    return true;
}

int64_t current_timestamp() {
    int64_t milliseconds;
    struct timespec te;
    clock_gettime(CLOCK_REALTIME, &te);
    milliseconds = 1000LL*te.tv_sec + round(te.tv_nsec/1e6);
    return milliseconds;
}

std::string strip_trailing_slash(std::string& input)
{
    if (input[input.size()-1] == '/') {
        input.resize(input.size()-1);
    }
    return input;
}

bool extract_file_extension(std::string& filepath, std::string& extension)
{
    bool extrecord = false;
    for (unsigned int i=0; i<filepath.size(); i++) {
        if (extrecord) {
            extension += filepath[i];
        }
        if (filepath[i] == 46) {
            extrecord = true;
        }
    }
    if (extrecord && extension.size() != 4) {
        extension.resize(4);
    }
    return extrecord;
}
