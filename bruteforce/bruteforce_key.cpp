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

constexpr static auto alphabet = cipher::base64::DEFAULT_ALPHABET;
constexpr static auto ati = cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY;
constexpr static auto decode_table = cipher::vigenere::create_decode_table(alphabet, ati);

template<auto ciphertext>
constexpr static auto translate_plaintext_vigenere(base64_key_bruteforce_state& state, const std::size_t ciphertext_index, const char char_to_translate)
{
    const auto char_to_translate_index = ati[static_cast<std::uint8_t>(char_to_translate)];
    const auto key_char_index = find_index(char_to_translate_index, ciphertext[ciphertext_index]);
    state.alloc(alphabet[key_char_index]);
}

template<std::size_t max_key_size, auto key_alphabet, auto ciphertext, auto heuristic, auto you_win, auto progress_report>
constexpr static void bruteforce_key_vigenere(base64_key_bruteforce_state& state)
{
    constexpr static auto get_next_char = []<auto next>(base64_key_bruteforce_state& state) {
        constexpr static auto decode = [](auto& state){
            const auto key_char = state.key[state.ciphertext_index % state.key_index];
            char source_char = ciphertext[state.ciphertext_index];

            const auto key_char_as_index = static_cast<std::uint8_t>(key_char);
            const auto source_char_as_index = static_cast<std::uint8_t>(source_char);
            source_char = decode_table[ati[source_char_as_index]][ati[key_char_as_index]];

            next(state, source_char);
        };
        if (state.key_index < max_key_size && !state.trying_repeat && state.key_index < ciphertext.size()) {
            state.template new_char<key_alphabet, decode>();
            if (state.key_index != 0) {
                const auto trying_repeat = state.trying_repeat;
                state.trying_repeat = true;
                decode(state);
                state.trying_repeat = trying_repeat;
            }
        } else {
            decode(state);
        }
    };

    bruteforce_base64<base64_key_bruteforce_state, ciphertext, get_next_char, heuristic, you_win, progress_report>(state);
}

constexpr static const auto ciphertext = cipher::buffer(
    "iW9cXmzOU7ZuZBtW40b3ngK2icE75R0V");

thread_local std::uint64_t iteration{0};
std::vector<base64_key_bruteforce_state> keys;
static void bruteforce_key(const std::string_view plaintext)
{
    constexpr static const auto max_key_size = 11;

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
    // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ \r\n0123456789");
    constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ");
    // constexpr static auto common_alphabet = cipher::alphabet::create("0123456789 ");
    constexpr static auto heuristic = [](const auto plain) {
        return cipher::is_in_alphabet<common_alphabet>(plain);
        // return cipher::is_print(plain);
        // return cipher::is_common_print(plain);
    };

    constexpr static auto key_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    // constexpr static auto key_alphabet = cipher::base64::DEFAULT_ALPHABET;

    (void)plaintext;
    auto state = base64_key_bruteforce_state{};
    // std::memcpy(state.key, plaintext.begin(), plaintext.size());
    // state.key_index = plaintext.size();

    // auto state = create_state_with_plaintext<base64_key_bruteforce_state, translate_plaintext_vigenere<ciphertext>>(plaintext);

    bruteforce_key_vigenere<max_key_size,
                            key_alphabet,
                            ciphertext,
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
