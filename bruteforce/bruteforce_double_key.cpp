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

constexpr static auto alphabet = cipher::base64::DEFAULT_ALPHABET;
constexpr static auto ati = cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY;
constexpr static auto table = cipher::vigenere::create_table(alphabet);
constexpr static auto decode_table = cipher::vigenere::create_decode_table(alphabet, ati);
constexpr static auto the_giant_first_decode = true;

constexpr static auto find_index(const std::uint8_t row_index, const char looking_for)
{
    for(auto i = 0u; i < table.size(); i++)
        if (table[row_index][i] == looking_for)
            return i;
    std::unreachable();
};

template<auto ciphertext, auto key>
constexpr static auto translate_plaintext_double_vigenere(base64_key_bruteforce_state& state, const std::size_t ciphertext_index, const char char_to_translate)
{
    const auto the_giant_key_char = key[ciphertext_index % key.size()];
    const auto the_giant_key_char_index = ati[static_cast<std::uint8_t>(the_giant_key_char)];
    const auto char_to_translate_index = ati[static_cast<std::uint8_t>(char_to_translate)];

    if constexpr (the_giant_first_decode) {
        const auto source_char_index = find_index(the_giant_key_char_index, ciphertext[ciphertext_index]);
        const auto key_char_index = find_index(char_to_translate_index, alphabet[source_char_index]);
        const auto c = alphabet[key_char_index];
        std::println("{} -> {} -> {}", char_to_translate, alphabet[source_char_index], ciphertext[ciphertext_index]);
        state.alloc(c);
        return;
    }

    const auto source_char = table[the_giant_key_char_index][char_to_translate_index];
    const auto source_char_index = ati[static_cast<std::uint8_t>(source_char)];
    const auto key_char_index = find_index(source_char_index, ciphertext[ciphertext_index]);
    state.alloc(alphabet[key_char_index]);
}

template<std::size_t max_key_size, auto key_alphabet, auto ciphertext, auto key, auto heuristic, auto you_win, auto progress_report>
constexpr static void bruteforce_key_vigenere(base64_key_bruteforce_state& state)
{
    constexpr static auto get_next_char = []<auto next>(base64_key_bruteforce_state& state) {
        constexpr static auto decode = [](auto& state){
            char key_chars[2]{ 0 };
            if constexpr (the_giant_first_decode) {
                key_chars[0] = key[state.ciphertext_index % key.size()];
                key_chars[1] = state.key[state.ciphertext_index % state.key_index];
            } else {
                key_chars[0] = state.key[state.ciphertext_index % state.key_index];
                key_chars[1] = key[state.ciphertext_index % key.size()];
            }
            char source_char = ciphertext[state.ciphertext_index];
            for(auto i = 0u; i < 2; i++) {
                const auto key_char_as_index = static_cast<std::uint8_t>(key_chars[i]);
                const auto source_char_as_index = static_cast<std::uint8_t>(source_char);
                source_char = decode_table[ati[source_char_as_index]][ati[key_char_as_index]];
            }

            next(state, source_char);
        };
        if (state.key_index < max_key_size && !state.trying_repeat) {
            state.template new_char<key_alphabet, decode>();
            const auto trying_repeat = state.trying_repeat;
            state.trying_repeat = true;
            decode(state);
            state.trying_repeat = trying_repeat;
        } else {
            decode(state);
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
    constexpr static const auto max_key_size = 17;

    constexpr static auto you_win = [](const auto& state) {
        keys.push_back(state);
        std::println("FOUND KEY: {:64} PLAINTEXT:\n{}", state.key_string_view(), state.plaintext_string_view());
    };
    constexpr static auto progress_report = [](const auto& state){
        if (iteration++ % 100000000 == 0) 
            std::println(stderr, "KEY: {:24} PLAIN:\n{:64}", state.key_string_view(), state.plaintext_string_view());
    };

    // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyz");
    // constexpr static auto common_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRTSUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!.,:@()\"'/\n\r\t ");
    // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ \r\n");
    // constexpr static auto common_alphabet = cipher::alphabet::create("0123456789 ");
    constexpr static auto heuristic = [](const auto plain) {
        // return cipher::is_in_alphabet<common_alphabet>(plain);
        return cipher::is_print(plain);
        // return cipher::is_common_print(plain);
    };

    // constexpr static auto key_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    constexpr static auto key_alphabet = cipher::base64::DEFAULT_ALPHABET;

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
                     "\nFOUND PLAIN:\n{}\nKEY: {}", key.plaintext_string_view(), key.key_string_view());

    std::println("done?");
}

int main(int, const char* argv[])
{
    bruteforce_key(std::string_view{ argv[1] });
    return 0;
}
