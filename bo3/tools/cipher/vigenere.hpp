#pragma once

#include <cstdint>
#include <span>

#include <cipher/alphabet.hpp>

namespace cipher::vigenere
{

template<size_t ALPHABET_LENGTH>
using VigenereTable = std::array<std::array<std::uint8_t, ALPHABET_LENGTH>, ALPHABET_LENGTH>;

template<size_t ALPHABET_LENGTH>
constexpr static VigenereTable<ALPHABET_LENGTH> create_table(const alphabet::Alphabet<ALPHABET_LENGTH>& alphabet)
{
    VigenereTable<ALPHABET_LENGTH> v;
    for(auto i = 0u; i < ALPHABET_LENGTH; i++)
        for(auto j = 0u; j < ALPHABET_LENGTH; j++)
            v[i][j] = alphabet[(i + j) % ALPHABET_LENGTH];
    return v;
}

template<bool autokey = true, std::size_t ALPHABET_LENGTH, std::size_t CIPHER_LENGTH, typename charT, typename charT2, typename charT3>
constexpr static void decode(const std::span<charT, CIPHER_LENGTH> decipher, 
                             const std::span<charT2, CIPHER_LENGTH> cipher, 
                             const std::span<charT3> key, 
                             const VigenereTable<ALPHABET_LENGTH>& vigenere, 
                             const alphabet::AsciiToIndexArray<ALPHABET_LENGTH>& ascii_to_index)
{
    for(auto i = 0u; i < CIPHER_LENGTH; i++) {
        unsigned char x;
        if constexpr (autokey)
            x = static_cast<unsigned char>(i < key.size() ? key[i] : decipher[i - key.size()]);
        else 
            x = static_cast<unsigned char>(key[i % key.size()]);
        decipher[i] = vigenere[ascii_to_index[cipher[i]]][ascii_to_index[x]];
    }
}

template<bool autokey = true, std::size_t ALPHABET_LENGTH, std::size_t CIPHER_LENGTH, typename charT, typename charT2, typename charT3>
constexpr static void encode(const std::span<charT, CIPHER_LENGTH> decipher, 
                             const std::span<charT2, CIPHER_LENGTH> cipher, 
                             const std::span<charT3> key, 
                             const VigenereTable<ALPHABET_LENGTH>& vigenere, 
                             const alphabet::AsciiToIndexArray<ALPHABET_LENGTH>& ascii_to_index)
{
    return decode(decipher, cipher, key, vigenere, ascii_to_index);
}

}
