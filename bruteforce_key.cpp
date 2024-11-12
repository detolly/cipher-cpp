#include <cstdio>
#include <cstring>
#include <print>
#include <vector>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/bruteforce.hpp>
#include <cipher/cipher.hpp>
#include <cipher/vigenere.hpp>

using namespace cipher::bruteforce;

#define THE_GIANT_FIRST 1
template<auto key> constexpr static auto get_first_key(const base64_key_bruteforce_state& state) {
#ifdef THE_GIANT_FIRST
    return std::span{ state.key, state.key_index };
#else
    return std::span{ key };
#endif
}
template<auto key> constexpr static auto get_second_key(const base64_key_bruteforce_state& state) {
#ifndef THE_GIANT_FIRST
    return std::span{ state.key, state.key_index };
#else
    return std::span{ key  };
#endif
}

// template<auto ciphertext>
// constexpr static auto translate_plaintext_vigenere(base64_key_bruteforce_state& state, const std::size_t ciphertext_index, const char char_to_translate)
// {
//     const auto source_char_index = cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY[static_cast<std::uint8_t>(ciphertext[ciphertext_index])];
//     
//     state.alloc();
// }

template<std::size_t max_key_size, auto plaintext_alphabet, auto ciphertext, auto key, auto heuristic, auto you_win, auto progress_report>
constexpr static void bruteforce_key_vigenere(base64_key_bruteforce_state& state)
{
    constexpr static auto get_next_char = [](base64_key_bruteforce_state& state, const std::size_t ciphertext_index, const auto& next) {
        const auto decode = [&](){
            const auto plain_char1 = cipher::vigenere::vigenere_one<false, false>(
                std::span{ ciphertext },
                std::span{ ciphertext },
                get_first_key<key>(state),
                std::span{ cipher::base64::DEFAULT_ALPHABET },
                cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY,
                ciphertext_index);

            const char temp[] = { plain_char1 };
            const auto plain_char2 = cipher::vigenere::vigenere_one<false, false>(
                std::span{ state.base64_plaintext, state.base64_plaintext_index },
                std::span{ temp, 1 },
                get_second_key<key>(state),
                std::span{ cipher::base64::DEFAULT_ALPHABET },
                cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY,
                ciphertext_index);

            auto was_trying_before = state.trying_repeat;
            state.trying_repeat = true;
            next(plain_char2);
            if (!was_trying_before) {
                state.trying_repeat = false;
                next(plain_char2);
            }
        };
        if (!state.trying_repeat && state.key_index < max_key_size) {
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
static void bruteforce_key(const std::string_view plaintext)
{
    constexpr static const auto max_key_size = 11;

    constexpr static auto you_win = [](const auto& ) {
        // keys.push_back(state);
        // std::println("FOUND KEY: {:64} PLAINTEXT: {}", state.key_string_view(), state.plaintext_string_view());
    };
    constexpr static auto progress_report = [](const auto& state){
        if (iteration++ % 100000000 == 0) 
            std::println(stderr, "KEY:\n{:24}\n\nPLAIN:\n{:64}\n", state.key_string_view(), state.plaintext_string_view());
    };

    constexpr static auto heuristic = [](const auto plain) {
        // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyz");
        constexpr static auto common_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRTSUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!.,:@()\"'/\n\r ");
        // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ \r\n");
        // constexpr static auto common_alphabet = cipher::alphabet::create("0123456789 ");
        return cipher::is_in_alphabet<common_alphabet>(plain);
        // return cipher::is_print(plain);
        // return cipher::is_common_print(plain);
    };

    auto state = base64_key_bruteforce_state{};
    std::memcpy(state.key, plaintext.begin(), plaintext.size());
    state.key_index = plaintext.size();

    bruteforce_key_vigenere<max_key_size,
                            cipher::alphabet::create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
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

int main(int, const char* argv[])
{
    bruteforce_key(std::string_view{ argv[1] });
    return 0;
}
