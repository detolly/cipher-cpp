#include <cstdio>
#include <print>
#include <vector>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/bruteforce.hpp>
#include <cipher/cipher.hpp>
#include <cipher/vigenere.hpp>

using namespace cipher::bruteforce;

template<auto plaintext_alphabet, auto ciphertext, auto key, auto heuristic, auto you_win, auto progress_report>
constexpr static void bruteforce_key_vigenere(base64_key_bruteforce_state& state)
{
    constexpr static auto get_next_char = [](base64_key_bruteforce_state& state, const std::size_t ciphertext_index, const auto& next) {
        const auto decode = [&](){
            const auto source_char = static_cast<std::uint8_t>(ciphertext[ciphertext_index]);
            const auto key_char = cipher::vigenere::key_character<false, false>(
                std::span{ state.base64_plaintext, state.base64_plaintext_index },
                std::span{ ciphertext },
                std::span{ key },
                ciphertext_index);
            const auto index = cipher::vigenere::alphabet_index<false>(
                cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY,
                static_cast<std::uint8_t>(cipher::base64::DEFAULT_ALPHABET.size()),
                source_char,
                key_char);
            const auto plain_giant_char = cipher::base64::DEFAULT_ALPHABET[index];

            const auto source_char2 = plain_giant_char;
            const auto key_char2 = cipher::vigenere::key_character<false, false>(
                std::span{ state.base64_plaintext, state.base64_plaintext_index },
                std::span{ &source_char2, 1 },
                std::span{ state.key, state.key_index },
                ciphertext_index);
            const auto index2 = cipher::vigenere::alphabet_index<false>(
                cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY,
                static_cast<std::uint8_t>(cipher::base64::DEFAULT_ALPHABET.size()),
                source_char2,
                key_char2);
            const auto c = cipher::base64::DEFAULT_ALPHABET[index2];
            auto was_trying_before = state.trying_repeat;
            state.trying_repeat = true;
            next(c);
            if (!was_trying_before) {
                state.trying_repeat = false;
                next(c);
            }
        };
        if (!state.trying_repeat) {
            state.template new_char<plaintext_alphabet>(decode);
        } else {
            decode();
        }
    };

    bruteforce_base64<base64_key_bruteforce_state, ciphertext, get_next_char, heuristic, you_win, progress_report>(state);
}

// constexpr static const auto ciphertext = cipher::buffer(
//     "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3");
constexpr static const auto ciphertext = cipher::buffer(
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");
constexpr const auto key = cipher::buffer("TheGiant");

thread_local std::uint64_t iteration{0};
std::vector<base64_key_bruteforce_state> keys;
static void bruteforce_key()
{
    constexpr static auto you_win = [](const auto& ) {
        // keys.push_back(state);
        // std::println("FOUND KEY: {:64} PLAINTEXT: {}", state.key_string_view(), state.plaintext_string_view());
    };
    constexpr static auto progress_report = [](const auto& state){
        if (iteration++ % 100000000 == 0) 
            std::println(stderr, "KEY: {:24} PLAIN: {:64} ", state.key_string_view(), state.plaintext_string_view());
    };

    constexpr static auto heuristic = [](const auto plain) {
        // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyz");
        // constexpr static auto common_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRTSUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!.,:@()\"'/\n\r ");
        // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ \r\n");
        // constexpr static auto common_alphabet = cipher::alphabet::create("0123456789 ");
        // return cipher::is_in_alphabet<common_alphabet>(plain);
        return cipher::is_print(plain);
        // return cipher::is_common_print(plain);
    };

    auto state = base64_key_bruteforce_state{};

    bruteforce_key_vigenere<cipher::base64::DEFAULT_ALPHABET,
                            ciphertext,
                            key,
                            heuristic,
                            you_win,
                            progress_report>(state);

    for(const auto& key : keys) {
        std::println(stderr, 
                     "FOUND PLAIN: {:64} KEY: {}", key.plaintext_string_view(), key.key_string_view());
    }

    std::println("done?");
}

int main(int, const char* [])
{
    bruteforce_key();
    return 0;
}
