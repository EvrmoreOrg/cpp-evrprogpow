
#include <ethash/progpow.hpp>
#include <iostream>

int main(int argc, const char* argv[])
{
    std::string str_header_hash;
    std::string str_mix_hash;
    std::string str_nonce;
    std::string str_boundary;

    for (int i = 0; i < argc; ++i)
    {
        const std::string arg{argv[i]};

        if (arg == "-h" && i + 1 < argc)
            str_header_hash = std::string(argv[++i]);
        else if (arg == "-m" && i + 1 < argc)
            str_mix_hash = std::string(argv[++i]);
        else if (arg == "-n" && i + 1 < argc)
            str_nonce = std::string(argv[++i]);
        else if (arg == "-b" && i + 1 < argc)
            str_boundary = std::string(argv[++i]);
    }

//    char final_hash[64];

//    if (progpow::light_verify(str_header_hash.c_str(), str_mix_hash.c_str(), str_nonce.c_str(), str_boundary.c_str(), final_hash))
//        printf("%.*s\n", 64, final_hash);
//    else {
//        printf("Not found\n");
//    }

    return 0;
}