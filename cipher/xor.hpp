#pragma once

#include <cstdint>
#include <span>

namespace cipher::Xor
{

template<typename charT, typename charT2, std::size_t ex1, std::size_t ex2>
constexpr static void Xor(const std::span<charT, ex1> cipher,
                          const std::span<charT2, ex2> xor_key)
{
    for(auto i = 0u; i < cipher.size(); i++)
        cipher[i] ^= xor_key[i % xor_key.size()];
}

}
