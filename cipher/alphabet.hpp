#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace cipher::alphabet
{

template<std::size_t ALPHABET_LENGTH, typename charT = char>
using alphabet_t = std::array<charT, ALPHABET_LENGTH>;

using ascii_to_index_t = std::array<std::uint8_t, 256>;

template<std::size_t ALPHABET_LENGTH>
constexpr static alphabet_t<ALPHABET_LENGTH-1> create(const char (&str)[ALPHABET_LENGTH])
{
    alphabet_t<ALPHABET_LENGTH - 1> arr;
    for(auto i = 0u; i < ALPHABET_LENGTH - 1; i++)
        arr[i] = str[i];
    return arr;
}

template<typename charT, std::size_t extent>
constexpr ascii_to_index_t create_ascii_to_index_array(const std::span<charT, extent> alphabet)
{
    ascii_to_index_t ascii_to_value{};
    for(std::uint8_t i = 0u; i < alphabet.size(); i++)
        ascii_to_value[static_cast<std::uint8_t>(alphabet[i])] = static_cast<std::uint8_t>(i);
    return ascii_to_value;
}

template<std::size_t ALPHABET_LENGTH>
constexpr ascii_to_index_t create_ascii_to_index_array(const alphabet_t<ALPHABET_LENGTH>& alphabet)
{
    ascii_to_index_t ascii_to_value{};
    for(std::uint8_t i = 0u; i < ALPHABET_LENGTH; i++)
        ascii_to_value[static_cast<std::uint8_t>(alphabet[i])] = static_cast<std::uint8_t>(i);
    return ascii_to_value;
}

}
