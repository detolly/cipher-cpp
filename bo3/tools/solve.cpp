#include <array>
#include <print>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/entropy.hpp>
#include <cipher/vigenere.hpp>
#include <cipher/xor.hpp>

using namespace std::string_view_literals;

// constexpr static const auto ciphertext = cipher::ciphertext(
// "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3");
constexpr static const auto ciphertext = cipher::buffer(
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");

// constexpr static const auto alphabet = cipher::alphabet::create("/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA");
constexpr static const auto vigenere_alphabet = cipher::base64::DEFAULT_ALPHABET;
constexpr static const auto ascii_to_index = cipher::alphabet::create_ascii_to_index_array(vigenere_alphabet);

// constexpr const std::string_view key = "VGhlR2lhbnRUaGVHaWFudFRoZUdpYW50"sv; // TheGiantTheGiantTheGiant
// constexpr const std::string_view key = "TheGiant"sv;

void rotate_vigenere(const std::span<char> key)
{
    for(auto k = 0u; k < vigenere_alphabet.size(); k++) {
        cipher::alphabet::Alphabet<vigenere_alphabet.size()> new_alphabet;
        for(auto i = 0u; i < vigenere_alphabet.size(); i++)
            new_alphabet[(i + k) % vigenere_alphabet.size()] = vigenere_alphabet[i];

        const auto rotated_vigenere_table = cipher::vigenere::create_table(new_alphabet);

        cipher::buffer_t<ciphertext.size()> vigenered;
        cipher::vigenere::decode(std::span { vigenered }, std::span { ciphertext }, key, rotated_vigenere_table, ascii_to_index);

        // std::println("Trying {}", std::string_view { vigenered.begin(), vigenered.end() });

        cipher::buffer_t<ciphertext.size() * 3 / 4> plaintext;
        cipher::base64::decode(std::span { plaintext }, std::span { vigenered });

        bool printable{ true };
        for(auto i = 0u; i < plaintext.size(); i++) {
            printable = std::isprint(plaintext[i]) && printable;
            if (!printable)
                break;
        }

        if (printable)
            std::println("PLAINTEXT: {}", cipher::buffer_to_string(plaintext));
    }
}

constexpr static const auto key_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"sv;
constexpr void make_key(char* key, size_t current_index, size_t size)
{
    for(auto i = 0u; i < key_alphabet.size(); i++) {
        key[current_index] = key_alphabet[i];
        rotate_vigenere(std::span<char>{ key, size });
        if (current_index + 1 < size)
            make_key(key, current_index + 1, size);
    }
}

template<std::size_t len>
constexpr static cipher::buffer_t<len - 1> encrypt_something(const char(&w)[len])
{
    constexpr static auto alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    constexpr static auto ascii_to_index = cipher::alphabet::create_ascii_to_index_array(alphabet);
    constexpr static auto table = cipher::vigenere::create_table(alphabet);

    auto plaintext = cipher::buffer(w);
    auto ciphertext = cipher::buffer_t<len - 1>{};

    cipher::vigenere::encode<false>(std::span{ ciphertext },
                                    std::span{ plaintext },
                                    std::span{ "FORTIFICATION" },
                                    table, 
                                    ascii_to_index);
    return ciphertext;
}

constexpr static auto whatever = encrypt_something("DEFENDTHEEASTWALLOFTHECASTLE");

int main()
{
    std::print("{}", cipher::buffer_to_string(whatever));

    // char key[13]{ 0 };
    // for(auto i = 0u; i < sizeof(key); i++)
    //     key[i] = key_alphabet[0];
    //
    // for(auto i = 1u; i < 13; i++)
    // {
    //     std::println("Key length: {}", i);
    //     make_key(key, 0, i);
    // }

}

