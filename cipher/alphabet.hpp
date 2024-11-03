#pragma once

#include <array>
#include <cstdint>

namespace cipher::alphabet
{

template<std::size_t ALPHABET_LENGTH>
using alphabet_t = std::array<std::uint8_t, ALPHABET_LENGTH>;

template<std::size_t ALPHABET_LENGTH>
using ascii_to_index_t = std::array<std::uint8_t, 256>;

template<std::size_t ALPHABET_LENGTH>
constexpr static alphabet_t<ALPHABET_LENGTH-1> create(const char (&str)[ALPHABET_LENGTH])
{
    alphabet_t<ALPHABET_LENGTH - 1> arr;
    for(auto i = 0u; i < ALPHABET_LENGTH - 1; i++)
        arr[i] = static_cast<std::uint8_t>(str[i]);
    return arr;
}

template<std::size_t ALPHABET_LENGTH>
constexpr ascii_to_index_t<ALPHABET_LENGTH> create_ascii_to_index_array(const alphabet_t<ALPHABET_LENGTH> alphabet)
{
    ascii_to_index_t<ALPHABET_LENGTH> ascii_to_value{};
    for(std::uint8_t i = 0u; i < ALPHABET_LENGTH; i++)
        ascii_to_value[alphabet[i]] = static_cast<std::uint8_t>(i);
    return ascii_to_value;
}

}
