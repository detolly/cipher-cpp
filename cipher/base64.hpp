#pragma once

#include <span>
#include <type_traits>

#include "alphabet.hpp"
#include "cipher/cipher.hpp"

namespace cipher::base64
{

constexpr static const auto DEFAULT_ALPHABET = alphabet::create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
constexpr static const auto DEFAULT_ASCII_TO_VALUE_ARRAY = alphabet::create_ascii_to_index_array(DEFAULT_ALPHABET);

template<std::size_t ALPHABET_LENGTH = DEFAULT_ALPHABET.size(), typename charT, typename charT2, std::size_t ex1, std::size_t ex2>
constexpr static void decode(
    const std::span<charT, ex1> target,
    const std::span<charT2, ex2> source,
    const alphabet::alphabet_t<ALPHABET_LENGTH>& = DEFAULT_ALPHABET,
    const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& ascii_to_value = DEFAULT_ASCII_TO_VALUE_ARRAY)
{
    if consteval {
        static_assert(source.size() % 4 == 0);
        static_assert(target.size() >= (source.size() * 3 / 4));
    }
    for(auto i = 0u; i < source.size() / 4; i++) {
        const auto char_1 = ascii_to_value[static_cast<std::uint8_t>(source[i * 4 + 0])];
        const auto char_2 = ascii_to_value[static_cast<std::uint8_t>(source[i * 4 + 1])];
        const auto char_3 = ascii_to_value[static_cast<std::uint8_t>(source[i * 4 + 2])];
        const auto char_4 = ascii_to_value[static_cast<std::uint8_t>(source[i * 4 + 3])];

        target[i * 3 + 0] = static_cast<charT>((char_1 << 2) + ((char_2 & 0x30) >> 4));
        target[i * 3 + 1] = static_cast<charT>(((char_2 & 0x0f) << 4) + ((char_3 & 0x3c) >> 2));
        target[i * 3 + 2] = static_cast<charT>(((char_3 & 0x03) << 6) + char_4);
    }
}

template<auto alphabet, typename charT, typename charT2, std::size_t ex1, std::size_t ex2>
constexpr static void decode(const std::span<charT, ex1> target,
                             const std::span<charT2, ex2> source)
{
    if consteval {
        static_assert(source.size() % 4 == 0);
        static_assert(target.size() >= (source.size() * 3 / 4));
    }
    for(auto i = 0u; i < source.size() / 4; i++) {
        const auto char_1 = cipher::index_in_alphabet<alphabet>(source[i * 4 + 0]);
        const auto char_2 = cipher::index_in_alphabet<alphabet>(source[i * 4 + 1]);
        const auto char_3 = cipher::index_in_alphabet<alphabet>(source[i * 4 + 2]);
        const auto char_4 = cipher::index_in_alphabet<alphabet>(source[i * 4 + 3]);

        target[i * 3 + 0] = static_cast<charT>((char_1 << 2) + ((char_2 & 0x30) >> 4));
        target[i * 3 + 1] = static_cast<charT>(((char_2 & 0x0f) << 4) + ((char_3 & 0x3c) >> 2));
        target[i * 3 + 2] = static_cast<charT>(((char_3 & 0x03) << 6) + char_4);
    }
}

}
