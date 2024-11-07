#include <array>
#include <cstdio>
#include <print>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/vigenere.hpp>

template<std::size_t alphabet_size>
struct Alphabet
{
    cipher::alphabet::alphabet_t<alphabet_size> alphabet;
    std::array<bool, alphabet_size> available_characters;
    cipher::alphabet::ascii_to_index_t<alphabet_size> ascii_to_index;

    constexpr Alphabet()
    {
        for(auto& b : available_characters)   b = true;
        for(auto& b : ascii_to_index)         b = static_cast<std::uint8_t>(-1);
        for(auto& b : alphabet)               b = '_';
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

    constexpr void add_to_configuration(const std::string_view config)
    {
        for(std::uint8_t i = 0u; i < config.length(); i++) {
            for(std::uint8_t j = 0u; j < available_characters.size(); j++) {
                if (!available_characters[j])
                    continue;
                alloc(j, config[i]);
                break;
            }
        }
    }

    constexpr void try_alloc_char(const char c, const auto& then)
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
    constexpr void try_alloc_index(const std::uint8_t i, const auto& then)
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
        }
    }

    constexpr static Alphabet<alphabet_size> create_starting_configuration(const std::string_view config)
    {
        Alphabet<alphabet_size> a;
        for(std::uint8_t i = 0u; i < config.length(); i++)
            a.alloc(i, config[i]);
        return a;
    }

    constexpr std::string_view string_view() const 
    {
        return std::string_view{ alphabet.begin(), alphabet.end() };
    }
};

template<auto ciphertext, auto get_next_char, auto heuristic, auto you_win>
constexpr static void bruteforce_base64_alphabet(Alphabet<64>& alphabet,
                                                 std::size_t ciphertext_index,
                                                 char* plain,
                                                 std::size_t plaintext_index)
{
    if (ciphertext_index >= ciphertext.size()) [[unlikely]] {
        you_win(alphabet, plain);
        return;
    }

    const auto base64_decode_fourth_char = [plain, plaintext_index, ciphertext_index, &alphabet](const char plain_base64_char){
        const auto value = cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY[static_cast<std::uint8_t>(plain_base64_char)];
        const auto old_value = plain[plaintext_index + 2];
        plain[plaintext_index + 2] = static_cast<char>(old_value + value);

        if (heuristic(std::span{ plain + plaintext_index, 3 }))
            bruteforce_base64_alphabet<ciphertext, get_next_char, heuristic, you_win>(alphabet, ciphertext_index + 4, plain, plaintext_index + 3);

        plain[plaintext_index + 2] = old_value;
    };

    const auto base64_decode_third_char = [&alphabet, plain, plaintext_index, &base64_decode_fourth_char](const char plain_base64_char){
        const auto value = cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY[static_cast<std::uint8_t>(plain_base64_char)];
        const auto old_value = plain[plaintext_index + 1];
        plain[plaintext_index + 1] = static_cast<char>(old_value + ((value & 0x3c) >> 2));
        plain[plaintext_index + 2] = static_cast<char>((value & 0x03) << 6);

        if (plain[plaintext_index + 2] & (1 << 7) || !heuristic(plain[plaintext_index + 1])) {
            plain[plaintext_index + 1] = old_value;
            plain[plaintext_index + 2] = 0;
            return;
        }

        get_next_char(alphabet, 3, base64_decode_fourth_char);

        plain[plaintext_index + 1] = old_value;
        plain[plaintext_index + 2] = 0;
    };

    const auto base64_decode_second_char = [plain, plaintext_index, &base64_decode_third_char, &alphabet](const char plain_base64_char){
        const auto value = cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY[static_cast<std::uint8_t>(plain_base64_char)];
        const auto old_value = plain[plaintext_index + 0];
        plain[plaintext_index + 0] = static_cast<char>(old_value + ((value & 0x30) >> 4));
        plain[plaintext_index + 1] = static_cast<char>((value & 0x0f) << 4);

        if (plain[plaintext_index + 1] & (1 << 7) || !heuristic(plain[plaintext_index])) {
            plain[plaintext_index + 0] = old_value;
            plain[plaintext_index + 1] = 0;
            return;
        }

        get_next_char(alphabet, 2, base64_decode_third_char);

        plain[plaintext_index + 0] = old_value;
        plain[plaintext_index + 1] = 0;
    };

    const auto base64_decode_first_char = [plain, plaintext_index, &base64_decode_second_char, &alphabet](const char plain_base64_char){
        const auto value = cipher::base64::DEFAULT_ASCII_TO_VALUE_ARRAY[static_cast<std::uint8_t>(plain_base64_char)];
        plain[plaintext_index + 0] = static_cast<char>(value << 2);

        if (!cipher::is_print(plain[plaintext_index])) {
            plain[plaintext_index + 0] = 0;
            return;
        }

        get_next_char(alphabet, 1, base64_decode_second_char);

        plain[plaintext_index + 0] = 0;
    };

    get_next_char(alphabet, 0, base64_decode_first_char);
}
