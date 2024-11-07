#include <array>
#include <cstdio>
#include <print>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/vigenere.hpp>
#include <cipher/bruteforce.hpp>

/*
    if (iteration++ % 100000000 == 0) [[unlikely]]
    // if (ciphertext_index > 4 * 1) [[unlikely]]
        std::println(stderr, "PLAIN: {:64} ALPHABET: {}", plain, std::string_view{ alphabet.begin(), alphabet.end() });

    if (ciphertext_index >= ciphertext.size()) [[unlikely]] {
        std::println("FOUND PLAIN: {:64} ALPHABET: {}", plain, alphabet.string_view());
        return;
    }
*/

template<auto plaintext_alphabet, auto ciphertext, auto key, auto heuristic, auto you_win>
constexpr static void bruteforce_alphabet_vigenere(Alphabet<64>& alphabet, char* plaintext)
{
    constexpr static auto get_next_char = [](Alphabet<64>& alphabet, const std::size_t ciphertext_index, const auto& next) {
        const auto source_char = ciphertext[ciphertext_index];
        const auto key_char = key[(ciphertext_index) % key.size()];
        alphabet.try_alloc_char(key_char, [&](const char key_char) {
            alphabet.try_alloc_char(source_char, [&](const char source_char) {
                const auto index = cipher::vigenere::alphabet_index<false, 64>(alphabet.ascii_to_index, source_char, key_char);
                alphabet.template try_alloc_index<plaintext_alphabet>(index, [&](const char c){
                    next(c);
                });
            });
        });
    };

    bruteforce_base64_alphabet<ciphertext, get_next_char, heuristic, you_win>(alphabet, 0, plaintext, 0);
}

template<auto plaintext_alphabet, auto ciphertext, auto key, auto heuristic, auto you_win>
constexpr static void bruteforce_alphabet_substitution(Alphabet<64>& alphabet, char* plaintext)
{
    constexpr static auto plaintext_ascii_to_value = cipher::alphabet::create_ascii_to_index_array(plaintext_alphabet);;

    constexpr static auto get_next_char = [](Alphabet<64>& alphabet, const std::size_t ciphertext_index, const auto& next) {
        const auto cipher_char = ciphertext[ciphertext_index];
        alphabet.template try_alloc_index<plaintext_alphabet>(plaintext_ascii_to_value[static_cast<std::uint8_t>(cipher_char)], [next](const char c){
            next(c);
        });
    };

    bruteforce_base64_alphabet<ciphertext, get_next_char, heuristic, you_win>(alphabet, 0, plaintext, 0);
}

constexpr static auto plaintext_alphabet = cipher::alphabet::create("/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA");
constexpr static const auto size = plaintext_alphabet.size();

// constexpr static const auto ciphertext = cipher::buffer(
//     "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3");
constexpr static const auto ciphertext = cipher::buffer(
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");
constexpr const auto key = cipher::buffer("TheGiant");

constexpr static auto heuristic = [](const auto plain) {
    // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyz");
    // constexpr static auto common_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRTSUVWXYZabcdefghijklmnopqrstuvwxyz1234567890.,");
    // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
    // constexpr static auto common_alphabet = cipher::alphabet::create("0123456789 ");

    // return cipher::is_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(plain);
    // return cipher::is_in_alphabet<common_alphabet>(plain);
    return cipher::is_print(plain);
    // return cipher::is_common_print(plain);
};

constexpr static auto you_win = [](const Alphabet<size>& state, char* plain) {
    std::println("FOUND ALPHABET: {:64} PLAINTEXT: {}", state.string_view(), std::string_view{ plain, ciphertext.size() });
};

static void bruteforce_alphabet()
{
    auto alphabet = Alphabet<size>::create_starting_configuration("TheGiant");
    char plaintext[ciphertext.size()]{ 0 };

    // bruteforce_alphabet_vigenere<plaintext_alphabet, ciphertext, key, heuristic, you_win>(alphabet, plaintext);
    bruteforce_alphabet_substitution<plaintext_alphabet, ciphertext, key, heuristic, you_win>(alphabet, plaintext);

    std::println("FINAL ALPHABET CONFIG: {} PLAINTEXT: {}", alphabet.string_view(), std::string_view{ plaintext, ciphertext.size() });
}

int main()
{
    bruteforce_alphabet();
    return 0;
}

