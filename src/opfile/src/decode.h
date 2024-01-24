#ifndef DECODE_H
#define DECODE_H

#include <string>
#include <vector>

bool check_chunk_contextual(std::string chunk, int& protocol, int& error_level);
bool is_valid_authchunk(std::string& chunk, int& error_level);
bool build_file_from_chunks(std::pair<std::string, std::string> get_info, int& error_level, int& total_chunks, std::vector<std::string>& encoded_chunks);

#endif // DECODE_H
