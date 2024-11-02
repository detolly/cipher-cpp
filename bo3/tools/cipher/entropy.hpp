#pragma once

#include <cmath>
#include <span>

namespace cipher::entropy
{

template<std::size_t LEN>
constexpr static float calculate_entropy(const std::span<const unsigned char, LEN> decipher) {

    unsigned char counted_bytes[256]{ 0 };
    for (auto j = 0u; j < LEN; j++)
        counted_bytes[decipher[j]]++;

    float entropy = 0.;
    for (int i = 0; i < 256; i++) {
        const float temp = static_cast<float>(counted_bytes[i]) / static_cast<float>(LEN);
        if (temp > 0.)
            entropy += temp * fabsf(log2f(temp));
    }

    return entropy;
}

}
