#include <cstdio>
#include <print>
#include <vector>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/vigenere.hpp>
#include <cipher/bruteforce.hpp>

using namespace cipher::bruteforce;

template<auto plaintext_alphabet, auto ciphertext, auto key, auto heuristic, auto you_win, auto progress_report>
constexpr static void bruteforce_alphabet_vigenere(base64_alphabet_bruteforce_state& state, char* plaintext)
{
    constexpr static auto get_next_char = [](base64_alphabet_bruteforce_state& state, const std::size_t ciphertext_index, const auto& next) {
        const auto source_char = ciphertext[ciphertext_index];
        const auto key_char = key[(ciphertext_index) % key.size()];
        state.alloc_at_all_index(key_char, [&](const char key_char) {
            state.alloc_at_all_index(source_char, [&](const char source_char) {
                const auto index = cipher::vigenere::alphabet_index<false, 64>(
                    state.ascii_to_index, 
                    source_char,
                    key_char);
                state.template alloc_all_char_at_index<plaintext_alphabet>(
                    index, 
                    [&](const char c){
                        next(c);
                    });
            });
        });
    };

    bruteforce_base64<ciphertext, get_next_char, heuristic, you_win, progress_report>(state, 0, plaintext, 0);
}

template<auto ciphertext>
constexpr static auto translate_plaintext_substitution(base64_alphabet_bruteforce_state& alphabet, const std::size_t ciphertext_index, const char char_to_translate)
{
    const auto source_char = ciphertext[ciphertext_index];
    const auto index = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(source_char);
    alphabet.try_alloc(index, char_to_translate);
}

template<auto ciphertext, auto heuristic, auto you_win, auto progress_report>
constexpr static void bruteforce_alphabet_substitution(base64_alphabet_bruteforce_state& state)
{
    constexpr static auto get_next_char = [](base64_alphabet_bruteforce_state& state, const std::size_t ciphertext_index, const auto& next) {
        const auto cipher_char = ciphertext[ciphertext_index];
        const auto cipher_index = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(cipher_char);
        state.template alloc_all_char_at_index<cipher::base64::DEFAULT_ALPHABET>(
            cipher_index ,
            [&](const char c){
                next(c);
            });
    };

    bruteforce_base64<base64_alphabet_bruteforce_state, ciphertext, get_next_char, heuristic, you_win, progress_report>(state);
}

// constexpr static const auto ciphertext = cipher::buffer(
//     "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3");
constexpr static const auto ciphertext = cipher::buffer(
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");
[[maybe_unused]] constexpr const auto key = cipher::buffer("TheGiant");

thread_local std::uint64_t iteration{0};
std::vector<base64_alphabet_bruteforce_state> alphabets;
static void bruteforce_alphabet(const std::string_view plaintext)
{
    constexpr static auto you_win = [](const auto& state) {
        alphabets.push_back(state);
        std::println("FOUND ALPHABET: {:64} PLAINTEXT: {}", state.alphabet_string_view(), state.plaintext_string_view());
    };
    constexpr static auto progress_report = [](const auto& state){
        if (iteration++ % 100000000 == 0) 
            std::println(stderr, "ALPHABET: {} PLAIN: \n{:64} ", state.plaintext_string_view(), state.alphabet_string_view());
    };

    constexpr static auto heuristic = [](const auto plain) {
        // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyz");
        // constexpr static auto common_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRTSUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!.,:@()\"'/\n\r ");
        // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
        // constexpr static auto common_alphabet = cipher::alphabet::create("0123456789 ");
        // return cipher::is_in_alphabet<common_alphabet>(plain);
        return cipher::is_print(plain);
        // return cipher::is_common_print(plain);
    };

    // auto alphabet = Base64Alphabet::create_starting_configuration("");
    // auto alphabet = Base64Alphabet::create_alphabet_with_plaintext<translate_plaintext_vigenere<plaintext_alphabet, ciphertext>>("Der Riese");
    auto state = base64_alphabet_bruteforce_state::create_state_with_plaintext<translate_plaintext_substitution<ciphertext>>(plaintext);

    // bruteforce_alphabet_vigenere<plaintext_alphabet, ciphertext, key, heuristic, you_win, progress_report>(alphabet, plaintext);
    bruteforce_alphabet_substitution<ciphertext, heuristic, you_win, progress_report>(state);

    for(const auto& alphabet : alphabets) {
        std::println(stderr, "FOUND PLAIN: {:64} ALPHABET: {}", alphabet.plaintext_string_view(), alphabet.alphabet_string_view());
    }

    std::println("done?", state.alphabet_string_view(), state.plaintext_string_view());
}

int main(int argc, const char* argv[])
{
    bruteforce_alphabet(std::string_view{ argv[1] });
    return 0;
}

