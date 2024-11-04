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
constexpr static vignere_table_t<ALPHABET_LENGTH, charT>
create_table(const alphabet::alphabet_t<ALPHABET_LENGTH, charT>& alphabet)
{
    vignere_table_t<ALPHABET_LENGTH, charT> v;
    for(auto i = 0u; i < ALPHABET_LENGTH; i++)
        for(auto j = 0u; j < ALPHABET_LENGTH; j++)
            v[i][j] = alphabet[(i + j) % ALPHABET_LENGTH];
    return v;
}

template<size_t ALPHABET_LENGTH, typename charT>
constexpr static vignere_table_t<ALPHABET_LENGTH, charT> 
create_decode_table(const alphabet::alphabet_t<ALPHABET_LENGTH, charT>& alphabet,
                    const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    vignere_table_t<ALPHABET_LENGTH, charT> v;
    for(auto i = 0u; i < ALPHABET_LENGTH; i++)
        for(auto j = 0u; j < ALPHABET_LENGTH; j++) {
            const auto c = static_cast<std::uint8_t>(alphabet[(i + j) % ALPHABET_LENGTH]);
            v[ascii_to_index[c]][i] = alphabet[j];
        }
    return v;
}

template<bool autokey, bool encode,
         typename charT, typename charT2, typename charT3,
         std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static std::uint8_t key_character(const std::span<charT, ex1> target,
                                            const std::span<charT2, ex2> source,
                                            const std::span<charT3, ex3> key,
                                            const std::size_t index)
{
    if constexpr (autokey) {
        if (index < key.size())
            return static_cast<std::uint8_t>(key[index]);
        if constexpr (encode)
            return static_cast<std::uint8_t>(source[index - key.size()]);
        return static_cast<std::uint8_t>(target[index - key.size()]);
    }

    return static_cast<std::uint8_t>(key[index % key.size()]);
}

template<bool autokey, bool encode, std::size_t ALPHABET_LENGTH,
         typename charT, typename charT2, typename charT3, typename charT4,
         std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static void vigenere(const std::span<charT, ex1> target,
                               const std::span<charT2, ex2> source,
                               const std::span<charT3, ex3> key,
                               const vignere_table_t<ALPHABET_LENGTH, charT4>& vigenere_table,
                               const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    static_assert(source.size() == target.size());
    for(auto i = 0u; i < source.size(); i++) {
        const auto key_char = key_character<autokey, encode>(target, source, key, i);
        const auto source_char = static_cast<std::uint8_t>(source[i]);

        target[i] = static_cast<charT>(vigenere_table[ascii_to_index[source_char]][ascii_to_index[key_char]]);
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

template<bool autokey, bool encode, std::size_t ALPHABET_LENGTH, typename charT, typename charT2, typename charT3, std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static void vigenere(const std::span<charT, ex1> target,
                               const std::span<charT2, ex2> source,
                               const std::span<charT3, ex3> key,
                               const alphabet::alphabet_t<ALPHABET_LENGTH>& alphabet,
                               const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    static_assert(source.size() == target.size());
    for(auto i = 0u; i < source.size(); i++) {
        const auto x = key_character<autokey, encode>(target, source, key, i);
        const auto z = static_cast<std::uint8_t>(source[i]);

        std::uint8_t index;
        if constexpr (encode) {
            index = (ascii_to_index[z] + ascii_to_index[x]) % ALPHABET_LENGTH;
        } else {
            if (ascii_to_index[z] < ascii_to_index[x]) {
                index = (ALPHABET_LENGTH - ascii_to_index[x] + ascii_to_index[z]);
            } else {
                index = (ascii_to_index[z] - ascii_to_index[x]) % ALPHABET_LENGTH;
            }
        }

        target[i] = static_cast<charT>(alphabet[index]);
    }
}

template<bool autokey, std::size_t ALPHABET_LENGTH, typename charT, typename charT2, typename charT3, std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static void encode(const std::span<charT, ex1> ciphertext,
                             const std::span<charT2, ex2> plaintext,
                             const std::span<charT3, ex3> key,
                             const alphabet::alphabet_t<ALPHABET_LENGTH>& alphabet,
                             const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    return vigenere<autokey, true>(ciphertext, plaintext, key, alphabet, ascii_to_index);
}

template<bool autokey, std::size_t ALPHABET_LENGTH, typename charT, typename charT2, typename charT3, std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static void decode(const std::span<charT, ex1> plaintext,
                             const std::span<charT2, ex2> ciphertext,
                             const std::span<charT3, ex3> key,
                             const alphabet::alphabet_t<ALPHABET_LENGTH>& alphabet,
                             const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_index)
{
    return vigenere<autokey, false>(plaintext, ciphertext, key, alphabet, ascii_to_index);
}


}
