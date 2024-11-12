#include "cipher/alphabet.hpp"
#include "cipher/base64.hpp"
#include <string_view>

#include <cipher/vigenere.hpp>

static std::string vigenere_encrypt(const std::string_view plaintext, const std::string_view key, const std::string_view alphabet, const cipher::alphabet::ascii_to_index_t& ascii_to_index)
{
    std::string ret;
    ret.reserve(plaintext.size());

    cipher::vigenere::encode<false>(std::span{ ret },
                                    std::span{ plaintext },
                                    std::span{ key },
                                    std::span{ alphabet },
                                    ascii_to_index);
    return ret;
}

constexpr const auto alphabet = cipher::base64::DEFAULT_ALPHABET;

int main(int, const char* argv[])
{
    std::println("{}", vigenere_encrypt(std::string_view{ argv[2] },
                                        std::string_view{ argv[1] },
                                        std::string_view{ alphabet.begin(), alphabet.end() },
                                        cipher::alphabet::create_ascii_to_index_array(alphabet)));
}
