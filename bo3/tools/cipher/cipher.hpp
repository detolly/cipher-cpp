#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace cipher
{

template<std::size_t BUFFER_LEN>
using buffer_t = std::array<std::uint8_t, BUFFER_LEN>;

template<std::size_t STRING_LEN, std::size_t BUFFER_LEN = STRING_LEN - 1> 
constexpr static buffer_t<BUFFER_LEN> buffer(const char (&plaintext)[STRING_LEN])
{
    buffer_t<BUFFER_LEN> arr{ 0 };
    for(auto i = 0u; i < BUFFER_LEN; i++)
        arr[i] = static_cast<std::uint8_t>(plaintext[i]);
    return arr;
}

// template<std::size_t size>
// constexpr static buffer_t<size> buffer()
// {
//     return buffer_t<size>{ 0 };
// }

template<std::size_t PLAINTEXT_LEN>
constexpr static std::string_view buffer_to_string(const buffer_t<PLAINTEXT_LEN>& plaintext)
{
    return std::string_view{ std::bit_cast<const char*>(plaintext.begin()), PLAINTEXT_LEN };
}

}
