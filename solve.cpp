#include <array>
#include <cstdio>
#include <print>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/entropy.hpp>
#include <cipher/vigenere.hpp>
#include <cipher/xor.hpp>

using namespace std::string_view_literals;


// constexpr static const auto vigenere_alphabet = cipher::alphabet::create("/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA");
constexpr static const auto vigenere_alphabet = cipher::base64::DEFAULT_ALPHABET;
// constexpr static const auto vigenere_ascii_to_index = cipher::alphabet::create_ascii_to_index_array(vigenere_alphabet);
// constexpr static const auto vigenere_decoding_table = cipher::vigenere::create_decode_table(vigenere_alphabet, vigenere_ascii_to_index);

constexpr static const auto VIGENERE_ALPHABET_SIZE = vigenere_alphabet.size();
constexpr static auto create_rotated_alphabets()
{
    std::array<cipher::alphabet::alphabet_t<VIGENERE_ALPHABET_SIZE>, VIGENERE_ALPHABET_SIZE> ret;
    for(auto i = 0u; i < VIGENERE_ALPHABET_SIZE; i++)
        for(auto j = 0u; j < VIGENERE_ALPHABET_SIZE; j++)
            ret[i][(i + j) % VIGENERE_ALPHABET_SIZE] = vigenere_alphabet[j];
    return ret;
}

constexpr static auto create_ascii_to_indexes(const auto& alphabets)
{
    std::array<cipher::alphabet::ascii_to_index_t<VIGENERE_ALPHABET_SIZE>, VIGENERE_ALPHABET_SIZE> ret;
    for(auto i = 0u; i < VIGENERE_ALPHABET_SIZE; i++)
        ret[i] = cipher::alphabet::create_ascii_to_index_array(alphabets[i]);
    return ret;
}

constexpr static auto create_decoding_tables(const auto& alphabets, const auto& ascii_to_indexes)
{
    std::array<cipher::vigenere::vignere_table_t<VIGENERE_ALPHABET_SIZE, char>, VIGENERE_ALPHABET_SIZE> ret;
    for(auto i = 0u; i < VIGENERE_ALPHABET_SIZE; i++)
        ret[i] = cipher::vigenere::create_decode_table(alphabets[i], ascii_to_indexes[i]);
    return ret;
}

template<std::size_t cipher_len, typename charT>
void rotate_vigenere(const std::span<const char, cipher_len> ciphertext, const std::span<charT> key)
{
    constexpr static const auto rotated_alphabets = create_rotated_alphabets();
    constexpr static const auto ascii_to_indexes = create_ascii_to_indexes(rotated_alphabets);
    constexpr static const auto decoding_tables = create_decoding_tables(rotated_alphabets, ascii_to_indexes);

    for(auto k = 0u; k < VIGENERE_ALPHABET_SIZE; k++) {
        auto vigenered = cipher::empty_buffer<cipher_len>();
        cipher::vigenere::encode<false>(std::span{ vigenered },
                                        std::span{ ciphertext },
                                        key,
                                        decoding_tables[k],
                                        ascii_to_indexes[k]);

        // std::println("Trying {}", cipher::buffer_to_string(vigenered));

        auto plaintext = cipher::empty_buffer<cipher_len * 3 / 4>();
        cipher::base64::decode(std::span{ plaintext },
                               std::span{ vigenered });

        bool printable{ true };
        for(auto i = 0u; i < plaintext.size(); i++) {
            printable = std::isprint(plaintext[i]);
            if (!printable)
                break;
        }

        if (printable) [[unlikely]]
            std::println("PLAINTEXT: {}", cipher::to_string(plaintext));
    }
}

// constexpr static const auto ciphertext = cipher::ciphertext(
// "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3");
constexpr static const auto ciphertext = cipher::buffer(
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");

constexpr static const auto key_alphabet = "TheGiant"sv;
constexpr void make_key(char* key, size_t current_index, size_t size)
{
    for(auto i = 0u; i < key_alphabet.size(); i++) {
        key[current_index] = key_alphabet[i];
        rotate_vigenere(std::span{ ciphertext },
                        std::span{ key, size });
        if (current_index + 1 < size)
            make_key(key, current_index + 1, size);
    }
}

static void bruteforce_key()
{
    char key[13]{ 0 };
    for(auto i = 0u; i < sizeof(key); i++)
        key[i] = key_alphabet[0];

    for(auto i = 1u; i < 13; i++) {
        std::println("Key length: {}", i);
        make_key(key, 0, i);
    }
}

constexpr const std::string_view key1 = "VGhlR2lhbnRUaGVHaWFudFRoZUdpYW50"sv; // TheGiantTheGiantTheGiant
constexpr const std::string_view key2 = "TheGiant"sv;

constexpr const auto keys = { key1, key2 };

void wordlist_key()
{
    for(const auto& key : keys)
        rotate_vigenere(std::span{ ciphertext },
                        std::span{ key });
}

int main()
{
    if constexpr (false) {
        bruteforce_key();
    }
    wordlist_key();
}

