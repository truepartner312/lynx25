#include "encode.h"
#include "decode.h"
#include "util.h"

// barrystyle 21062023

static bool run_parse_encode_decode(std::string filepath, int& error_level)
{
    int total_chunks;
    std::vector<std::string> encoded_chunks;

    // turn filepath into chunks
    if (!build_chunks_with_headers(filepath, error_level, total_chunks, encoded_chunks)) {
        printf("failure during chunk generation (err: %d)\n", error_level);
        return false;
    }

    // turn chunks into filepath
    if (!build_file_from_chunks(filepath + ".bak", error_level, total_chunks, encoded_chunks)) {
        printf("failure during file construction (err: %d)\n", error_level);
        return false;
    }

    return true;
}

int main()
{
    int64_t t1, t2;
    int testsz, error_level;
    std::string base_testfile = "test/test.bin";

    testsz = 16;

    for (int i=0; i<24; i++) {

        t1 = current_timestamp();

        printf("\ngenerating random binary of %d bytes\n", testsz);
        generate_random_binary(base_testfile, testsz);
        if (!run_parse_encode_decode(base_testfile, error_level)) {
            printf("test failed at size %d (errorlevel %d)\n", i, testsz);
            return false;
        }

        printf("comparing source and destination file\n");
        if (!compare_two_binary_files(base_testfile, base_testfile + ".bak")) {
            printf("test failed at size %d (files arent identical)\n", i, testsz);
            return false;
        }

        t2 = current_timestamp();

        printf("passed testsz of %d bytes (took %llums)\n", testsz, t2 - t1);
        testsz *= 2;
    }

    return true;
}

