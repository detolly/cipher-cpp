#pragma once

#include <print>
#include <cstdint>
#include <span>

#include "alphabet.hpp"

namespace cipher::vigenere
{

template<size_t ALPHABET_LENGTH>
using vignere_table_t = std::array<std::array<std::uint8_t, ALPHABET_LENGTH>, ALPHABET_LENGTH>;

template<size_t ALPHABET_LENGTH>
constexpr static vignere_table_t<ALPHABET_LENGTH> create_table(const alphabet::alphabet_t<ALPHABET_LENGTH>& alphabet)
{
    vignere_table_t<ALPHABET_LENGTH> v;
    for(auto i = 0u; i < ALPHABET_LENGTH; i++)
        for(auto j = 0u; j < ALPHABET_LENGTH; j++)
            v[i][j] = alphabet[(i + j) % ALPHABET_LENGTH];
    return v;
}

template<size_t ALPHABET_LENGTH>
constexpr static vignere_table_t<ALPHABET_LENGTH> create_decode_table(const alphabet::alphabet_t<ALPHABET_LENGTH>& alphabet, const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    vignere_table_t<ALPHABET_LENGTH> v;
    for(auto i = 0u; i < ALPHABET_LENGTH; i++)
        for(auto j = 0u; j < ALPHABET_LENGTH; j++)
            v[ascii_to_index[alphabet[(i + j) % ALPHABET_LENGTH]]][i] = alphabet[j];
    return v;
}

template<bool autokey, std::size_t ALPHABET_LENGTH, typename charT, typename charT2, typename charT3, std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static void vigenere(const std::span<charT, ex1> target, 
                             const std::span<charT2, ex2> source, 
                             const std::span<charT3, ex3> key, 
                             const vignere_table_t<ALPHABET_LENGTH>& vigenere_table, 
                             const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    static_assert(source.size() == target.size());
    for(auto i = 0u; i < source.size(); i++) {
        unsigned char x;
        if constexpr (autokey) {
            x = static_cast<unsigned char>(i < key.size() ? key[i] : target[i - key.size()]);
        } else {
            x = static_cast<unsigned char>(key[i % key.size()]);
        }

        target[i] = vigenere_table[ascii_to_index[source[i]]][ascii_to_index[x]];
    }
}

}
