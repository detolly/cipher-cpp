#include <array>
#include <cstdio>
#include <print>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/vigenere.hpp>

namespace cipher::bruteforce
{

struct base64_alphabet_bruteforce_state
{
    cipher::alphabet::alphabet_t<64> alphabet;
    std::array<bool, 64> available_characters;
    cipher::alphabet::ascii_to_index_t<64> ascii_to_index;
    char plaintext[1024]{ 0 };
    std::size_t plaintext_index{ 0 };
    std::size_t ciphertext_index{ 0 };

    constexpr base64_alphabet_bruteforce_state()
    {
        for(auto& b : available_characters)   b = true;
        for(auto& b : ascii_to_index)         b = static_cast<std::uint8_t>(-1);
        for(auto& b : alphabet)               b = '_';
    }

    constexpr std::string_view plaintext_string_view() const
    {
        return std::string_view{ plaintext, plaintext_index };
    }

    constexpr void alloc(const std::uint8_t index, const char c)
    {
        available_characters[index] = false;
        alphabet[index] = c;
        ascii_to_index[static_cast<std::uint8_t>(c)] = index;
    }

    constexpr void dealloc(const std::uint8_t index)
    {
        ascii_to_index[static_cast<std::uint8_t>(alphabet[index])] = static_cast<std::uint8_t>(-1);
        available_characters[index] = true;
        alphabet[index] = '_';
    }

    constexpr void add_to_alphabet(const std::string_view letters)
    {
        for(std::uint8_t i = 0u; i < letters.length(); i++) {
            for(std::uint8_t j = 0u; j < available_characters.size(); j++) {
                if (!available_characters[j])
                    continue;
                alloc(j, letters[i]);
                break;
            }
        }
    }

    constexpr void try_alloc(const std::uint8_t index, const char c)
    {
        if (available_characters[index])
            alloc(index, c);
    }

    constexpr void alloc_at_all_index(const char c, const auto& then)
    {
        if (ascii_to_index[static_cast<std::uint8_t>(c)] != static_cast<std::uint8_t>(-1)) {
            then(c);
            return;
        }

        for(std::uint8_t i = 0u; i < available_characters.size(); i++) {
            if (!available_characters[i])
                continue;
            alloc(i, c);
            then(c);
            dealloc(i);
        }
    }

    template<auto alphabet>
    constexpr void alloc_all_char_at_index(const std::uint8_t i, const auto& then)
    {
        if (!available_characters[i]) {
            then(alphabet[i]);
            return;
        }

        for(const char c : alphabet) {
            if (ascii_to_index[static_cast<std::uint8_t>(c)] != static_cast<std::uint8_t>(-1))
                continue;
            alloc(i, c);
            then(c);
            dealloc(i);
        }
    }

    constexpr static base64_alphabet_bruteforce_state create_starting_configuration(const std::string_view config)
    {
        base64_alphabet_bruteforce_state a;
        for(std::uint8_t i = 0u; i < config.length(); i++)
            a.alloc(i, config[i]);
        return a;
    }

    template<auto translate_and_alloc>
    constexpr static base64_alphabet_bruteforce_state create_state_with_plaintext(const std::string_view plaintext)
    {
        base64_alphabet_bruteforce_state a;

        for(auto i = 0u; i < plaintext.size() / 3; i++) {
            const auto plain = plaintext.substr(i*3, 3);
            char c1 = cipher::base64::DEFAULT_ALPHABET[static_cast<std::uint8_t>((plain[0] & 0b11111100) >> 2)];
            char c2 = cipher::base64::DEFAULT_ALPHABET[static_cast<std::uint8_t>(((plain[0] & 0b00000011) << 4) | ((plain[1] & 0b11110000) >> 4))];
            char c3 = cipher::base64::DEFAULT_ALPHABET[static_cast<std::uint8_t>(((plain[1] & 0b00001111) << 2) | ((plain[2] & 0b11000000) >> 6))];
            char c4 = cipher::base64::DEFAULT_ALPHABET[static_cast<std::uint8_t>(plain[2] & 0b00111111)];

            translate_and_alloc(a, i * 4, c1);
            translate_and_alloc(a, i * 4 + 1, c2);
            translate_and_alloc(a, i * 4 + 2, c3);
            translate_and_alloc(a, i * 4 + 3, c4);

            a.plaintext[i * 3] = plain[0];
            a.plaintext[i * 3 + 1] = plain[1];
            a.plaintext[i * 3 + 2] = plain[2];

            a.plaintext_index += 3;
            a.ciphertext_index += 4;
        }

        const auto left = plaintext.size() % 3;
        if (left == 1) {
            char c1 = cipher::base64::DEFAULT_ALPHABET[static_cast<std::uint8_t>((plaintext[plaintext.size() - 1] & 0b11111100) >> 2)];
            translate_and_alloc(a, a.ciphertext_index, c1);
            a.plaintext[a.plaintext_index] = plaintext[plaintext.size() - 1];
            a.plaintext_index += 1;
            a.ciphertext_index += 1;
        } else if (left == 2) {
            char c1 = cipher::base64::DEFAULT_ALPHABET[static_cast<std::uint8_t>((plaintext[plaintext.size() - 2] & 0b11111100) >> 2)];
            char c2 = cipher::base64::DEFAULT_ALPHABET[static_cast<std::uint8_t>(((plaintext[plaintext.size() - 2] & 0b00000011) << 4) | ((plaintext[plaintext.size() - 1] & 0b11110000) >> 4))];
            translate_and_alloc(a, a.ciphertext_index, c1);
            translate_and_alloc(a, a.ciphertext_index + 1, c2);
            a.plaintext[a.plaintext_index] = plaintext[plaintext.size() - 2];
            a.plaintext[a.plaintext_index + 1] = plaintext[plaintext.size() - 1];
            a.plaintext_index += 2;
            a.ciphertext_index += 2;
        }

        return a;
    }

    constexpr std::string_view string_view() const 
    {
        return std::string_view{ alphabet.begin(), alphabet.end() };
    }
};

struct config
{
    base64_alphabet_bruteforce_state alphabet;
    char plain[3];
};

template<auto ciphertext, auto get_next_char, auto heuristic, auto you_win, auto progress_report>
constexpr static void bruteforce_base64_alphabet(base64_alphabet_bruteforce_state& alphabet)
{
    progress_report(alphabet);

    if (alphabet.ciphertext_index >= ciphertext.size()) [[unlikely]] {
        you_win(alphabet);
        return;
    }

    const auto base64_decode_fourth_char = [&alphabet](const char plain_base64_char){
        auto& third_char = alphabet.plaintext[alphabet.plaintext_index + 2];
        const auto value = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(plain_base64_char);
        const auto old_value = third_char;

        third_char = static_cast<char>(old_value + value);
        if (heuristic(third_char)) {
            alphabet.plaintext_index += 3;
            alphabet.ciphertext_index += 4;
            bruteforce_base64_alphabet<ciphertext, get_next_char, heuristic, you_win, progress_report>(alphabet);
            alphabet.plaintext_index -= 3;
            alphabet.ciphertext_index -= 4;
        }
        third_char = old_value;
    };

    const auto base64_decode_third_char = [&alphabet, base64_decode_fourth_char](const char plain_base64_char){
        auto& second_char = alphabet.plaintext[alphabet.plaintext_index + 1];
        auto& third_char = alphabet.plaintext[alphabet.plaintext_index + 2];
        const auto value = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(plain_base64_char);
        const auto old_value = second_char;

        second_char = static_cast<char>(old_value + ((value & 0x3c) >> 2));
        third_char = static_cast<char>((value & 0x03) << 6);
        if ((third_char & (1 << 7)) == 0 && heuristic(second_char))
            get_next_char(alphabet, alphabet.ciphertext_index + 3, base64_decode_fourth_char);

        second_char = old_value;
        third_char = 0;
    };

    const auto base64_decode_second_char = [&alphabet, base64_decode_third_char](const char plain_base64_char){
        auto& first_char = alphabet.plaintext[alphabet.plaintext_index + 0];
        auto& second_char = alphabet.plaintext[alphabet.plaintext_index + 1];
        const auto value = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(plain_base64_char);
        const auto old_value = first_char;

        first_char = static_cast<char>(old_value + ((value & 0x30) >> 4));
        second_char = static_cast<char>((value & 0x0f) << 4);
        if ((second_char & (1 << 7)) == 0 && heuristic(first_char))
            get_next_char(alphabet, alphabet.ciphertext_index + 2, base64_decode_third_char);

        first_char = old_value;
        second_char = 0;
    };

    const auto base64_decode_first_char = [&alphabet, base64_decode_second_char](const char plain_base64_char){
        auto& first_char = alphabet.plaintext[alphabet.plaintext_index + 0];
        const auto value = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(plain_base64_char);

        first_char = static_cast<char>(value << 2);
        if (cipher::is_print(first_char))
            get_next_char(alphabet, alphabet.ciphertext_index + 1, base64_decode_second_char);

        first_char = 0;
    };

    get_next_char(alphabet, alphabet.ciphertext_index, base64_decode_first_char);
}

}
