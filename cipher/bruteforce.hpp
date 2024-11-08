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
            dealloc(i);
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

template<auto ciphertext, auto get_next_char, auto heuristic, auto you_win, auto progress_report>
constexpr static void bruteforce_base64_alphabet(Alphabet<64>& alphabet,
                                                 std::size_t ciphertext_index,
                                                 char* plain,
                                                 std::size_t plaintext_index)
{
    progress_report(alphabet, plain);

    if (ciphertext_index >= ciphertext.size()) [[unlikely]] {
        you_win(alphabet, plain);
        return;
    }

    const auto base64_decode_fourth_char = [plain, plaintext_index, ciphertext_index, &alphabet](const char plain_base64_char){
        auto& third_char = plain[plaintext_index + 2];
        const auto value = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(plain_base64_char);
        const auto old_value = third_char;

        third_char = static_cast<char>(old_value + value);
        if (heuristic(third_char))
            bruteforce_base64_alphabet<ciphertext, get_next_char, heuristic, you_win, progress_report>(
                alphabet,
                ciphertext_index + 4,
                plain,
                plaintext_index + 3);

        third_char = old_value;
    };

    const auto base64_decode_third_char = [&alphabet, plain, ciphertext_index, plaintext_index, &base64_decode_fourth_char](const char plain_base64_char){
        auto& second_char = plain[plaintext_index + 1];
        auto& third_char = plain[plaintext_index + 2];
        const auto value = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(plain_base64_char);
        const auto old_value = second_char;

        second_char = static_cast<char>(old_value + ((value & 0x3c) >> 2));
        third_char = static_cast<char>((value & 0x03) << 6);
        if ((third_char & (1 << 7)) == 0 && heuristic(plain[plaintext_index + 1]))
            get_next_char(alphabet, ciphertext_index + 3, base64_decode_fourth_char);

        second_char = old_value;
        third_char = 0;
    };

    const auto base64_decode_second_char = [plain, plaintext_index, ciphertext_index, &base64_decode_third_char, &alphabet](const char plain_base64_char){
        auto& first_char = plain[plaintext_index + 0];
        auto& second_char = plain[plaintext_index + 1];
        const auto value = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(plain_base64_char);
        const auto old_value = first_char;

        first_char = static_cast<char>(old_value + ((value & 0x30) >> 4));
        second_char = static_cast<char>((value & 0x0f) << 4);
        if ((second_char & (1 << 7)) == 0 && heuristic(first_char))
            get_next_char(alphabet, ciphertext_index + 2, base64_decode_third_char);

        first_char = old_value;
        second_char = 0;
    };

    const auto base64_decode_first_char = [plain, plaintext_index, ciphertext_index, &base64_decode_second_char, &alphabet](const char plain_base64_char){
        auto& first_char = plain[plaintext_index + 0];
        const auto value = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(plain_base64_char);

        first_char = static_cast<char>(value << 2);
        if (cipher::is_print(first_char))
            get_next_char(alphabet, ciphertext_index + 1, base64_decode_second_char);

        first_char = 0;
    };

    get_next_char(alphabet, ciphertext_index, base64_decode_first_char);
}
