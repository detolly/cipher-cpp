#include <array>
#include <cstdio>
#include <print>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/entropy.hpp>
#include <cipher/vigenere.hpp>
#include <cipher/xor.hpp>

// constexpr static const auto ciphertext = cipher::ciphertext(
// "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3");
constexpr static const auto ciphertext = cipher::buffer(
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");
constexpr const auto key = cipher::buffer("TheGiant");
constexpr static auto plaintext_alphabet = cipher::base64::DEFAULT_ALPHABET;

static void test_alphabet(cipher::alphabet::alphabet_t<plaintext_alphabet.size()>& alphabet,
                          std::array<bool, plaintext_alphabet.size()>& available_characters,
                          cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()>& ascii_to_index,
                          std::size_t ciphertext_index)
{
    if (ciphertext_index >= ciphertext.size()) {
        std::println("{}", std::string_view{ alphabet.begin(), alphabet.end() });
        return;
    }

    const auto alloc_place = [&](std::uint8_t i, char c) {
        available_characters[i] = false;
        alphabet[i] = c;
        ascii_to_index[static_cast<std::uint8_t>(c)] = i;
    };
    const auto dealloc_place = [&](std::uint8_t i) {
        ascii_to_index[static_cast<std::uint8_t>(alphabet[i])] = 0;
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

                cipher::buffer_t<1, char> plaintext;
                cipher::vigenere::decode<false>(std::span{ plaintext.begin(), 1 },
                                                std::span{ ciphertext.begin() + index, 1 },
                                                std::span{ key },
                                                alphabet,
                                                ascii_to_index);
                pred(plaintext);
                dealloc_place(j);
            }
            dealloc_place(i);
        }
    };

    char bin[3];

    const auto pred4 = [&](const auto& plaintext){
        bin[2] += plaintext[0];
        if (cipher::is_print(std::span{ bin, 3 })) [[unlikely]] {
            const char chars_to_place[] = { ciphertext[ciphertext_index + 1], key[(ciphertext_index + 1) % key.size()] };
            move_forward(chars_to_place, 2, [&]([[maybe_unused]] const auto& plaintext){
                test_alphabet(alphabet, available_characters, ascii_to_index, ciphertext_index + 4);
            });
        }
    };

    const auto pred3 = [&](const auto& plaintext){
        bin[1] += static_cast<char>((plaintext[0] & 0x3c) >> 2);
        bin[2] = static_cast<char>((plaintext[0] & 0x3) << 6);
        if (!cipher::is_print(std::span{ bin, 2 })) [[likely]]
            return;
        if (bin[2] & (1 << 7))
            return;

        const char chars_to_place[] = { ciphertext[ciphertext_index + 3], key[(ciphertext_index + 3) % key.size()] };
        move_forward(chars_to_place, 2, pred4);
    };

    const auto pred2 = [&](const auto& plaintext){
        bin[0] += static_cast<char>((plaintext[0] & 0x30) >> 4);
        bin[1] = static_cast<char>((plaintext[0] & 0xf) << 4);
        if (bin[1] & (1 << 7))
            return;

        const char chars_to_place[] = { ciphertext[ciphertext_index + 2], key[(ciphertext_index + 2) % key.size()] };
        move_forward(chars_to_place, 2, pred3);
    };

    const auto pred1 = [&](const auto& plaintext){
        bin[0] = static_cast<char>(plaintext[0] << 2);
        if (!cipher::is_print(std::span{ bin, 1 }))
            return;

        const char chars_to_place[] = { ciphertext[ciphertext_index + 1], key[(ciphertext_index + 1) % key.size()] };
        move_forward(chars_to_place, 1, pred2);
    };

    const char chars_to_place[] = { ciphertext[ciphertext_index], key[(ciphertext_index) % key.size()] };
    move_forward(chars_to_place, 0, pred1);
}


static void bruteforce_alphabet()
{
    cipher::alphabet::alphabet_t<plaintext_alphabet.size()> cipher_alphabet{};
    cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()> cipher_ascii_to_index{};
    std::array<bool, plaintext_alphabet.size()> available_characters{ 0 };
    for(auto& b : available_characters)
        b = true;

    test_alphabet(cipher_alphabet, available_characters, cipher_ascii_to_index, 0);
}

int main()
{
    bruteforce_alphabet();
    return 0;
}

