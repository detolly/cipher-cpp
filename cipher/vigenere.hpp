#pragma once

#include <print>
#include <cstdint>
#include <span>

#include "alphabet.hpp"

namespace cipher::vigenere
{

template<size_t ALPHABET_LENGTH, typename charT>
using vignere_table_t = std::array<std::array<charT, ALPHABET_LENGTH>, ALPHABET_LENGTH>;

template<size_t ALPHABET_LENGTH, typename charT>
constexpr static vignere_table_t<ALPHABET_LENGTH, charT> create_table(const alphabet::alphabet_t<ALPHABET_LENGTH, charT>& alphabet)
{
    vignere_table_t<ALPHABET_LENGTH, charT> v;
    for(auto i = 0u; i < ALPHABET_LENGTH; i++)
        for(auto j = 0u; j < ALPHABET_LENGTH; j++)
            v[i][j] = alphabet[(i + j) % ALPHABET_LENGTH];
    return v;
}

template<size_t ALPHABET_LENGTH, typename charT>
constexpr static vignere_table_t<ALPHABET_LENGTH, charT> create_decode_table(const alphabet::alphabet_t<ALPHABET_LENGTH, charT>& alphabet, const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    vignere_table_t<ALPHABET_LENGTH, charT> v;
    for(auto i = 0u; i < ALPHABET_LENGTH; i++)
        for(auto j = 0u; j < ALPHABET_LENGTH; j++)
            v[ascii_to_index[static_cast<std::uint8_t>(alphabet[(i + j) % ALPHABET_LENGTH])]][i] = alphabet[j];
    return v;
}

template<bool autokey, bool encode, std::size_t ALPHABET_LENGTH, typename charT, typename charT2, typename charT3, typename charT4, std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static void vigenere(const std::span<charT, ex1> target, 
                             const std::span<charT2, ex2> source, 
                             const std::span<charT3, ex3> key, 
                             const vignere_table_t<ALPHABET_LENGTH, charT4>& vigenere_table, 
                             const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    static_assert(source.size() == target.size());
    for(auto i = 0u; i < source.size(); i++) {
        std::uint8_t x;
        if constexpr (autokey) {
            if (i < key.size())  {
                x = static_cast<std::uint8_t>(key[i]);
            } else {
                std::uint8_t y;
                if constexpr (encode) {
                    y = static_cast<std::uint8_t>(source[i - key.size()]);
                } else {
                    y = static_cast<std::uint8_t>(target[i - key.size()]);
                }
                x = y;
            }
        } else {
            x = static_cast<std::uint8_t>(key[i % key.size()]);
        }

        const auto z = static_cast<std::uint8_t>(source[i]);
        target[i] = static_cast<charT>(vigenere_table[ascii_to_index[z]][ascii_to_index[x]]);
    }
}

template<bool autokey, std::size_t ALPHABET_LENGTH, typename charT, typename charT2, typename charT3, typename charT4, std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static void encode(const std::span<charT, ex1> ciphertext, 
                             const std::span<charT2, ex2> plaintext, 
                             const std::span<charT3, ex3> key, 
                             const vignere_table_t<ALPHABET_LENGTH, charT4>& encoding_table, 
                             const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    return vigenere<autokey, true>(ciphertext, plaintext, key, encoding_table, ascii_to_index);
}

template<bool autokey, std::size_t ALPHABET_LENGTH, typename charT, typename charT2, typename charT3, typename charT4, std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static void decode(const std::span<charT, ex1> plaintext, 
                             const std::span<charT2, ex2> ciphertext, 
                             const std::span<charT3, ex3> key, 
                             const vignere_table_t<ALPHABET_LENGTH, charT4>& decoding_table, 
                             const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    return vigenere<autokey, false>(plaintext, ciphertext, key, decoding_table, ascii_to_index);
}


}
