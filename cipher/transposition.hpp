#include <algorithm>
#include <vector>
#include <print>

#include <cipher/alphabet.hpp>

namespace cipher::transposition
{

template<bool encode = true,
         typename charT1, typename charT2, typename charT3,
         std::size_t ex1, std::size_t ex2, std::size_t ex3>
constexpr static void column(const std::span<charT1, ex1> target,
                             const std::span<charT2, ex2> source,
                             const std::span<charT3, ex3> key,
                             const cipher::alphabet::ascii_to_index_t& ascii_to_index)
{
    std::vector<std::tuple<std::uint8_t, std::uint8_t>> sorted_keys;
    sorted_keys.reserve(key.size());
    for(auto i = 0u; i < key.size(); i++)
        sorted_keys.push_back({ i, ascii_to_index[static_cast<std::uint8_t>(key[i])] });

    std::sort(sorted_keys.begin(), sorted_keys.end(), [](const auto& a, const auto& b){
        return std::get<1>(b) > std::get<1>(a);
    });

    const auto num_rows = (target.size() / key.size()) + 1;
    for(auto i = 0u; i < key.size(); i++) {
        for(auto row = 0u; row < num_rows; row++) {
            if (i * key.size() + i >= target.size())
                break;
            const auto column_index = std::get<0>(sorted_keys[i]);
            const auto linear_index = row * key.size() + i;
            const auto fixed_index = row * key.size() + column_index;
            if constexpr (encode)
                target[linear_index] = source[fixed_index];
            else
                target[fixed_index] = source[linear_index];
        }
    }
}

}
