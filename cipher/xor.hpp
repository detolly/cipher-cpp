#pragma once

#include <cstdint>

namespace cipher::Xor
{

constexpr static void Xor(unsigned char* cipher, const std::size_t size, const unsigned char* xor_key, const std::size_t xor_key_size)
{
    for(auto i = 0u; i < size; i++)
        cipher[i] ^= xor_key[i % xor_key_size];
}

}
