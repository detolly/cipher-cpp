#pragma once

#include <span>

#include "alphabet.hpp"

namespace cipher::substitution
{

template<typename charT, typename charT2, typename charT3, std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static void substitute(const std::span<charT, ex1> target,
                                 const std::span<charT2, ex2> source,
                                 const alphabet::ascii_to_index_t& source_ascii_to_index,
                                 const std::span<charT3, ex3>& target_alphabet)
{
    for(auto i = 0u; i < target.size(); i++) {
        target[i] = target_alphabet[source_ascii_to_index[static_cast<std::uint8_t>(source[i])]];
    }
}

}
