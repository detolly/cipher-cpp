#pragma once

#include <span>

#include "alphabet.hpp"

namespace cipher::base64
{

constexpr static const auto DEFAULT_ALPHABET = alphabet::create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
constexpr static const auto DEFAULT_ASCII_TO_VALUE_ARRAY = alphabet::create_ascii_to_index_array(DEFAULT_ALPHABET);

template<std::size_t ALPHABET_LENGTH = DEFAULT_ALPHABET.size(), typename charT, typename charT2, std::size_t ex1, std::size_t ex2>
constexpr static void decode(
    const std::span<charT, ex1> decipher,
    const std::span<charT2, ex2> cipher,
    const alphabet::alphabet_t<ALPHABET_LENGTH>& = DEFAULT_ALPHABET,
    const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_value = DEFAULT_ASCII_TO_VALUE_ARRAY)
{
    static_assert(cipher.size() % 4 == 0);
    static_assert(decipher.size() >= (cipher.size() * 3 / 4));
    for(auto i = 0u; i < cipher.size() / 4; i++) {
        const auto pos_of_char_1 = ascii_to_value[static_cast<std::uint8_t>(cipher[i*4 + 1])];
        const auto pos_of_char_2 = ascii_to_value[static_cast<std::uint8_t>(cipher[i*4 + 2])];

        decipher[i*3 + 0] = static_cast<charT>((ascii_to_value[static_cast<std::uint8_t>(cipher[i*4])] << 2) + ((pos_of_char_1 & 0x30) >> 4));
        decipher[i*3 + 1] = static_cast<charT>(((pos_of_char_1 & 0x0f) << 4) + ((pos_of_char_2 & 0x3c) >> 2));
        decipher[i*3 + 2] = static_cast<charT>(((pos_of_char_2 & 0x03) << 6) + ascii_to_value[static_cast<std::uint8_t>(cipher[i*4 + 3])]);
    }
}

}
