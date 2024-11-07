#include <array>
#include <cstdio>
#include <print>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/entropy.hpp>
#include <cipher/vigenere.hpp>
#include <cipher/xor.hpp>

using namespace std::string_view_literals;

constexpr static const auto alphabet = cipher::alphabet::create("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/");
constexpr static const auto ascii_to_value= cipher::alphabet::create_ascii_to_index_array(alphabet);
// constexpr static const auto alphabet = cipher::base64::DEFAULT_ALPHABET;
// constexpr static const auto ascii_to_value= cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY;

constexpr static const auto ciphertext = cipher::buffer(
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");

constexpr static const auto key = cipher::buffer("TheGiant");
constexpr static const auto times = 100000;
constexpr static const auto autokey = true;

static void many_times()
{
    auto buffer = ciphertext;
    auto buffer2 = cipher::empty_buffer<ciphertext.size()>();
    auto b64buffer = cipher::empty_buffer<ciphertext.size() * 3 / 4>();

    for(auto i = 0u; i < times; i++)
    {
        cipher::vigenere::decode<autokey>(std::span{ buffer2 },
                                          std::span{ buffer },
                                          std::span{ key },
                                          alphabet,
                                          ascii_to_value);
        buffer = buffer2;
        cipher::base64::decode(std::span{ b64buffer },
                               std::span{ buffer2 });

        if(cipher::is_print(std::span{ b64buffer }))
            std::println("{}", cipher::to_string(b64buffer));
    }
}

int main()
{
    many_times();
    return 0;
}

