#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <span>

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

template<typename charT, std::size_t ex>
constexpr static bool is_print(const std::span<charT, ex> w) {
    for(auto i = 0u; i < w.size(); i++) {
        const auto c = static_cast<const std::uint8_t>(w[i]);
        if (c < 0x20) return false;
        if (c > 0x7e) return false;
    }
    return true;
}

}
