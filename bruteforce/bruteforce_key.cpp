#include <cstdio>
#include <cstring>
#include <print>
#include <vector>
#include <utility>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/bruteforce.hpp>
#include <cipher/cipher.hpp>
#include <cipher/vigenere.hpp>

using namespace cipher::bruteforce;

constexpr static auto alphabet = cipher::alphabet::create("DAFCBEGHLINKJMOPTQVSRUWXbYdaZcefjglihkmnrotqpsuvzw1yx023749658+/");
// constexpr static auto alphabet = cipher::base64::DEFAULT_ALPHABET;
constexpr static auto ati = cipher::alphabet::create_ascii_to_index_array(alphabet);
constexpr static auto table = cipher::vigenere::create_table(alphabet);
constexpr static auto decode_table = cipher::vigenere::create_decode_table(alphabet, ati);

constexpr static auto find_index(const std::uint8_t row_index, const char looking_for)
{
    for(auto i = 0u; i < table.size(); i++)
        if (table[row_index][i] == looking_for)
            return i;
    std::unreachable();
};


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
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");
// constexpr static const auto ciphertext = cipher::buffer(
//     "78NpigQbEfgceud4PiY7e4VBzwvK/NiIkcJUGFYtsR9wHOjIDhToIqKXy3aWHp7wtkm6PJLJ1T3aey3DeYy5GAJU45O+l+5arQsvvLIGEY4CjepIlc2dMD4PVwkE7ohkorAoZrJbwZB4IlNJW1frZ8OWpX0lcvdI3hxtb8XDkfplBkGs0B9gbtJXaFUnD/4jjX58T6Hz0ogb+zhaY3yxakbpW/GQbkZ7i+AS4E44GEV35gUCew45SwMvAO/C7PORVJtHvlVipfgNg4UU+ZQzPjG/W/D9wo3JGmbyYO+D+8J3yeD44nsTkDnXQXFH6lsCch9Br/SWza62/xEaIqI8My2fvY9XC+RJ8n3AUtDQpi/P7SF/q4MiFEu4CxTgN9xPIJq9mQGTJukIakRagOLX3sStqXObTAI11UFyNQJEUhO6AL2zb04XxBIJ08ckMAWqajVXyYZA4VEj4BYo/CXRXq74uV7nhBcNFC4mSOZqV5/zgdoeDDUoyl61jmqk8bDW7rJMuX2FR69a8iNcjWFRf7BQ9Wd0RSTYE2R6OGMXplgEeH9chnA4+fytYBHwQSXaOPzffy/IVUpGtnRXYfc6u2pRegr2GTjspmqFkDbnToquwH2TS+b5BbyThs9twn/UW/GqTOYX490/fcDnRfKcY3uNf4yO/jwIPa9PyV61UURrF9rjejZ29TbRsABRhYLHDdlqBEvJ9wA5kB4xJ7my3OL87aHizxd+/Y0+XO7U57S8E050ToDSJZAKeJwc3k1GPBpUCnwUn9Gv1+mJa+gx+c/sc07yssr47pGifWZrJHi7+QC8OgRJgFHz+Fb09OZE+sFEKcOm2IEtPQWOGOpHjQSGUlV6/qzgy9EIgWAGI1rOoxOrpizaBY5yxrFphkQOOUyTBG8CvYLVvxucVApi6s7f7ce+F+WWs/yh0G8VuZMXkzHJHYU0+nOhjXUy3drEOvvlaoTbTng0QImPdQrKQvoSr0qb9NJZVY5njNbvHLacL65FSlA3pX5WkrXDJVP64FKD413Zh+dGKO11B16mVZsn3zycljbOxzrRBW7aJ/C8hYcM1LoHeHCKLvuUTx7oaoEWiD+NAVzjeLiS3jB2zP33C9bSTPc5WjC0piSNgly/67Fvl1YpCZbbopN5rmXkRo9TKa+2VWUmiqVIO7PnMlK+A05v/etvxOHb069JRA9xGOvuIZXp2hwn7B2daJ2xGD/YS2Hcz+KQG4qQWqbVDVrjW4+46LPSp/CJCy6bHh6+RTAgwgV4GR6Zmd0hgQYeXG1IDYIW6ZXxoKEoLK5zqKNkYPWOqoHeeh2ivZM+TSKGxpnlBko50RQ5nTXWJlYo5LsgUEHrlqoDjinBsfBWmdB92g1W8R5PI2qrTMmk2PzY9Br/bIjbvOSgs6IOrrFOuODjlnJzVlm7ptl");

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

    // (void)plaintext;
    // auto state = base64_key_bruteforce_state{};
    // std::memcpy(state.key, plaintext.begin(), plaintext.size());
    // state.key_index = plaintext.size();

    auto state = create_state_with_plaintext<base64_key_bruteforce_state, translate_plaintext_vigenere<ciphertext>>(plaintext);

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
