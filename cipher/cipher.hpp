#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <span>

#include "alphabet.hpp"

namespace cipher
{

template<std::size_t BUFFER_LEN, typename charT>
using buffer_t = std::array<charT, BUFFER_LEN>;

template<std::size_t STRING_LEN, std::size_t BUFFER_LEN = STRING_LEN - 1> 
constexpr static buffer_t<BUFFER_LEN, char> buffer(const char (&plaintext)[STRING_LEN])
{
    buffer_t<BUFFER_LEN, char> arr{ 0 };
    for(auto i = 0u; i < BUFFER_LEN; i++)
        arr[i] = plaintext[i];
    return arr;
}

template<std::size_t len, typename charT = char> 
constexpr static buffer_t<len, charT> empty_buffer()
{
    return buffer_t<len, charT>{ 0 };
}

template<std::size_t len>
constexpr static std::string_view to_string(const buffer_t<len, char>& buffer)
{
    return std::string_view{ buffer.begin(), buffer.end() };
}

constexpr static bool is_print(const char c) {
    if (c < 0x20) return false;                  // obvious
    if (c > 0x7A) return false;                  // obvious
    return true;
}

template<typename charT, std::size_t ex>
constexpr static bool is_print(const std::span<charT, ex> w) {
    for(auto i = 0u; i < w.size(); i++) {
        if (!is_print(w[i]))
            return false;
    }
    return true;
}

template<alphabet::alphabet_t alphabet, typename charT>
constexpr static bool char_is_in_alphabet(const charT c) {
    for(const auto a : alphabet)
        if (c == a) return true;
    return false;
}

template<alphabet::alphabet_t alphabet, typename charT, std::size_t ex>
constexpr static bool char_is_in_alphabet(const std::span<charT, ex> w) {
    for(auto i = 0u; i < w.size(); i++) {
        if (!char_is_in_alphabet<alphabet>(w[i]))
            return false;
    }
    return true;
}


}
