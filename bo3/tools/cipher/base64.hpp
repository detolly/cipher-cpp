#pragma once

#include <span>

#include "alphabet.hpp"

namespace cipher::base64
{

constexpr static const auto DEFAULT_ALPHABET = alphabet::create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
constexpr static const auto DEFAULT_ASCII_TO_VALUE_ARRAY = alphabet::create_ascii_to_index_array(DEFAULT_ALPHABET);

template<std::size_t ENCODED_LENGTH, std::size_t ALPHABET_LENGTH = DEFAULT_ALPHABET.size(), typename charT, typename charT2>
constexpr static void decode(
    const std::span<charT, ENCODED_LENGTH * 3 / 4> decipher,
    const std::span<charT2, ENCODED_LENGTH> cipher,
    const alphabet::Alphabet<ALPHABET_LENGTH>& = DEFAULT_ALPHABET,
    const alphabet::AsciiToIndexArray<ALPHABET_LENGTH>& ascii_to_value = DEFAULT_ASCII_TO_VALUE_ARRAY) requires(ENCODED_LENGTH % 4 == 0)
{

    for(auto i = 0u; i < ENCODED_LENGTH / 4; i++) {
        const auto pos_of_char_1 = ascii_to_value[cipher[i*4 + 1]];
        decipher[i*3] = static_cast<std::uint8_t>((ascii_to_value[cipher[i*4]] << 2) + ((pos_of_char_1 & 0x30) >> 4));
        const auto pos_of_char_2 = ascii_to_value[cipher[i*4 + 2]];
        decipher[i*3 + 1] = static_cast<std::uint8_t>(((pos_of_char_1 & 0x0f) << 4) + ((pos_of_char_2 & 0x3c) >> 2));
        decipher[i*3 + 2] = static_cast<std::uint8_t>(((pos_of_char_2 & 0x03) << 6) + ascii_to_value[cipher[i*4 + 3]]);
    }
}

}
