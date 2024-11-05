#include <array>
#include <cstdio>
#include <print>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/entropy.hpp>
#include <cipher/vigenere.hpp>
#include <cipher/xor.hpp>
#include <thread>

// constexpr static const auto ciphertext = cipher::buffer(
// "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3");
constexpr static const auto ciphertext = cipher::buffer(
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");
constexpr const auto key = cipher::buffer("TheGiant");
constexpr static auto plaintext_alphabet = cipher::base64::DEFAULT_ALPHABET;

std::uint64_t i = 0;

static void test_alphabet(cipher::alphabet::alphabet_t<plaintext_alphabet.size()>& alphabet,
                          std::array<bool, plaintext_alphabet.size()>& available_characters,
                          cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()>& ascii_to_index,
                          std::size_t ciphertext_index,
                          char plain[ciphertext.size()],
                          std::size_t plaintext_index)
{
    // if (i++ % 1000000 == 0) [[unlikely]]
        std::println(stderr, "PLAIN: {} INDEX: {} ALPHABET: {}", plain, ciphertext_index, std::string_view{ alphabet.begin(), alphabet.end() });

    if (ciphertext_index >= ciphertext.size()) {
        std::println("ALPHABET: {}", std::string_view{ alphabet.begin(), alphabet.end() });
        return;
    }

    const auto alloc_place = [&](std::uint8_t i, char c) {
        available_characters[i] = false;
        alphabet[i] = c;
        ascii_to_index[static_cast<std::uint8_t>(c)] = i;
    };
    const auto dealloc_place = [&](std::uint8_t i) {
        ascii_to_index[static_cast<std::uint8_t>(alphabet[i])] = static_cast<std::uint8_t>(-1);
        available_characters[i] = true;
        alphabet[i] = 0;
    };

    const auto move_forward = [&](const char chars_to_place[2], std::size_t index, auto pred) {
        for(std::uint8_t i = 0u; i < available_characters.size(); i++) {
            if (!available_characters[i])
                continue;

            alloc_place(i, chars_to_place[0]);
            for(std::uint8_t j = 0u; j < available_characters.size(); j++) {
                if (!available_characters[j])
                    continue;

                alloc_place(j, chars_to_place[1]);

                const auto source_char = static_cast<std::uint8_t>(ciphertext[ciphertext_index + index]);
                const auto key_char = cipher::vigenere::key_character<false, false>(
                    std::span{ plain, plaintext_index + index },
                    std::span{ ciphertext.begin() + ciphertext_index + index, 1 },
                    std::span{ key },
                    ciphertext_index + index);

                const auto index = cipher::vigenere::alphabet_index<false, 64>(ascii_to_index, source_char, key_char);
                if (!available_characters[index]) {
                    pred(alphabet[index]);
                } else {
                    for(const char c : plaintext_alphabet) {
                        if (ascii_to_index[static_cast<std::uint8_t>(c)] == static_cast<std::uint8_t>(-1)) {
                            alloc_place(index, c);
                            pred(c);
                            dealloc_place(index);
                        }
                    }
                }
                dealloc_place(j);
            }
            dealloc_place(i);
        }
    };

    const auto pred4 = [&](const char plaintext){
        plain[plaintext_index + 2] += plaintext;
        if (cipher::is_print(std::span{ plain + plaintext_index, 3 })) {
            const char chars_to_place[] = { ciphertext[ciphertext_index + 4], key[(ciphertext_index + 4) % key.size()] };
            move_forward(chars_to_place, 2, [&]([[maybe_unused]] const auto& plaintext){
                test_alphabet(alphabet, available_characters, ascii_to_index, ciphertext_index + 4, plain, plaintext_index + 3);
            });
        }
    };

    const auto pred3 = [&](const char plaintext){
        plain[plaintext_index + 1] += static_cast<char>((plaintext & 0x3c) >> 2);
        plain[plaintext_index + 2] = static_cast<char>((plaintext & 0x3) << 6);
        if (!cipher::is_print(plain[plaintext_index + 1]))
            return;
        if (plain[plaintext_index + 2] & (1 << 7))
            return;

        const char chars_to_place[] = { ciphertext[ciphertext_index + 3], key[(ciphertext_index + 3) % key.size()] };
        move_forward(chars_to_place, 2, pred4);
    };

    const auto pred2 = [&](const char plaintext){
        plain[plaintext_index + 0] += static_cast<char>((plaintext & 0x30) >> 4);
        plain[plaintext_index + 1] = static_cast<char>((plaintext & 0xf) << 4);
        if (plain[plaintext_index + 1] & (1 << 7))
            return;

        const char chars_to_place[] = { ciphertext[ciphertext_index + 2], key[(ciphertext_index + 2) % key.size()] };
        move_forward(chars_to_place, 2, pred3);
    };

    const auto pred1 = [&](const char plaintext){
        plain[plaintext_index + 0] = static_cast<char>(plaintext << 2);
        if (!cipher::is_print(static_cast<char>(plaintext << 2)))
            return;

        const char chars_to_place[] = { ciphertext[ciphertext_index + 1], key[(ciphertext_index + 1) % key.size()] };
        move_forward(chars_to_place, 1, pred2);
    };

    const char chars_to_place[] = { ciphertext[ciphertext_index], key[(ciphertext_index) % key.size()] };
    move_forward(chars_to_place, 0, pred1);
}

static void bruteforce_alphabet()
{
    for(auto i = plaintext_alphabet.size() - 1; i >= 0; i--) {
        cipher::alphabet::alphabet_t<plaintext_alphabet.size()> cipher_alphabet{ 0 };
        cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()> cipher_ascii_to_index{(std::uint8_t)-1};
        std::array<bool, plaintext_alphabet.size()> available_characters{ 0 };
        for(auto& b : available_characters)
            b = true;

        cipher_alphabet[0] = plaintext_alphabet[i];
        cipher_ascii_to_index[(std::uint8_t)plaintext_alphabet[i]] = 0;
        available_characters[0] = false;

        char plaintext[ciphertext.size()]{ 0 };
        test_alphabet(cipher_alphabet, available_characters, cipher_ascii_to_index, 0, plaintext, 0);
    }

}

int main()
{
    bruteforce_alphabet();
    return 0;
}

