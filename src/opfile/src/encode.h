#ifndef ENCODE_H
#define ENCODE_H

#include <string>
#include <vector>

bool build_chunks_with_headers(std::pair<std::string, std::string>& putinfo, int& error_level, int& total_chunks, std::vector<std::string>& encoded_chunks);

#endif // ENCODE_H
