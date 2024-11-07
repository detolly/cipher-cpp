#pragma once

#include <span>

#include "alphabet.hpp"

namespace cipher::substitution
{

template<std::size_t ALPHABET_LENGTH, typename charT, typename charT2, std::size_t ex1, std::size_t ex2>
constexpr static void substitute(const std::span<charT, ex1> target,
                             const std::span<charT2, ex2> source,
                             const alphabet::ascii_to_index_t<ALPHABET_LENGTH>& source_ascii_to_index,
                             const alphabet::alphabet_t<ALPHABET_LENGTH>& target_alphabet)
{
    if consteval {
        static_assert(source.size() == target.size());
    }
    for(auto i = 0u; i < target.size(); i++) {
        target[i] = target_alphabet[source_ascii_to_index[source[i]]];
    }
}

}
