#include <cstdio>
#include <cstring>
#include <print>
#include <utility>
#include <vector>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/bruteforce.hpp>
#include <cipher/cipher.hpp>
#include <cipher/vigenere.hpp>

using namespace cipher::bruteforce;

#define THE_GIANT_FIRST_DECODE 1
template<auto key>
constexpr static auto get_first_key([[maybe_unused]] const base64_key_bruteforce_state& state) {
#ifdef THE_GIANT_FIRST_DECODE
    return std::span{ state.key, state.key_index };
#else
    return std::span{ key };
#endif
}
template<auto key>
constexpr static auto get_second_key([[maybe_unused]] const base64_key_bruteforce_state& state) {
#ifndef THE_GIANT_FIRST_DECODE
    return std::span{ state.key, state.key_index };
#else
    return std::span{ key  };
#endif
}

template<auto ciphertext, auto key>
constexpr static auto translate_plaintext_double_vigenere(base64_key_bruteforce_state& state, const std::size_t ciphertext_index, const char char_to_translate)
{
    constexpr static auto table = cipher::vigenere::create_table(cipher::base64::DEFAULT_ALPHABET);
    constexpr static auto atv = cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY;
    constexpr static auto alphabet = cipher::base64::DEFAULT_ALPHABET;

    constexpr static auto find_index = [](const std::uint8_t row_index, const char looking_for) {
        for(auto i = 0u; i < table.size(); i++)
            if (table[row_index][i] == looking_for)
                return i;
        std::unreachable();
    };

    const auto the_giant_key_char = key[ciphertext_index % key.size()];
    const auto the_giant_key_char_index = atv[static_cast<std::uint8_t>(the_giant_key_char)];
    const auto char_to_translate_index = atv[static_cast<std::uint8_t>(char_to_translate)];

#ifdef THE_GIANT_FIRST_DECODE
    const auto source_char_index = find_index(the_giant_key_char_index, ciphertext[ciphertext_index]);
    const auto key_char_index = find_index(char_to_translate_index, alphabet[source_char_index]);
#else
    const auto source_char = table[the_giant_key_char_index][char_to_translate_index];
    const auto source_char_index = atv[static_cast<std::uint8_t>(source_char)];
    const auto key_char_index = find_index(source_char_index, ciphertext[ciphertext_index]);
#endif
    state.alloc(alphabet[key_char_index]);
}

template<std::size_t max_key_size, auto key_alphabet, auto ciphertext, auto key, auto heuristic, auto you_win, auto progress_report>
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
            state.template new_char<key_alphabet>(decode);
        } else {
            decode();
        }
    };

    bruteforce_base64<base64_key_bruteforce_state, ciphertext, get_next_char, heuristic, you_win, progress_report>(state);
}

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

    constexpr static auto you_win = [](const auto& state) {
        keys.push_back(state);
        std::println("FOUND KEY: {:64} PLAINTEXT: \n{}", state.key_string_view(), state.plaintext_string_view());
    };
    constexpr static auto progress_report = [](const auto& state){
        if (iteration++ % 100000000 == 0) 
            std::println(stderr, "KEY: {:24} PLAIN:\n{:64}", state.key_string_view(), state.plaintext_string_view());
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

    constexpr static auto key_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");

    // auto state = base64_key_bruteforce_state{};
    // std::memcpy(state.key, plaintext.begin(), plaintext.size());
    // state.key_index = plaintext.size();

    auto state = create_state_with_plaintext<base64_key_bruteforce_state, translate_plaintext_double_vigenere<ciphertext, key>>(plaintext);

    bruteforce_key_vigenere<max_key_size,
                            key_alphabet,
                            ciphertext,
                            key,
                            heuristic,
                            you_win,
                            progress_report>(state);

    for(const auto& key : keys)
        std::println(stderr, 
                     "FOUND PLAIN:\n{}\nKEY: {}", key.plaintext_string_view(), key.key_string_view());

    std::println("done?");
}

int main(int, const char* argv[])
{
    bruteforce_key(std::string_view{ argv[1] });
    return 0;
}
