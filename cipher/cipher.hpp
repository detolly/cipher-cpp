#pragma once

#include <array>
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

constexpr static bool is_common_print(const char c) {
    if (c == 0x20) return true;
    if (c < 0x30) return false;
    if (c > 0x7A) return false;

    if (c > 0x3A && c < 0x41) return false;
    if (c > 0x5B && c < 0x61) return false;

    return true;
}

template<typename charT, std::size_t ex>
constexpr static bool is_common_print(const std::span<charT, ex> w)
{
    for(auto i = 0u; i < w.size(); i++)
        if (!is_common_print(w[i]))
            return false;

    return true;
}

constexpr static bool is_print(const char c) {
    if (c < 0x20) return false;
    if (c > 0x7A) return false;
    return true;
}

template<typename charT, std::size_t ex>
constexpr static bool is_print(const std::span<charT, ex> w)
{
    for(auto i = 0u; i < w.size(); i++)
        if (!is_print(w[i]))
            return false;

    return true;
}

template<auto alphabet>
constexpr static bool is_in_alphabet(const char c)
{
    for(const auto a : alphabet)
        if (c == a) return true;
    return false;
}

template<auto alphabet, typename charT, std::size_t extent>
constexpr static bool is_in_alphabet(const std::span<charT, extent> w)
{
    for(auto i = 0u; i < w.size(); i++) {
        if (!is_in_alphabet<alphabet>(static_cast<char>(w[i])))
            return false;
    }
    return true;
}


}
