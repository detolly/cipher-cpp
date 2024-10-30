#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <print>

using namespace std::string_view_literals;

constexpr static float calculate_entropy(const unsigned char* decipher, const size_t len) {

    unsigned char counted_bytes[256]{ 0 };
    for (auto j = 0u; j < len; j++)
        counted_bytes[decipher[j]]++;

    float entropy = 0.;
    for (int i = 0; i < 256; i++) {
        const float temp = static_cast<float>(counted_bytes[i]) / static_cast<float>(len);
        if (temp > 0.)
            entropy += temp * fabsf(log2f(temp));
    }

    return entropy;
}

constexpr static void decode(unsigned char* decipher, const unsigned char* cipher, const std::size_t size, const unsigned char (&ascii_to_value)[256]){
    for(auto i = 0u; i < size / 4; i++)
    {
        const auto pos_of_char_1 = ascii_to_value[cipher[i*4 + 1]];
        decipher[i*3] = static_cast<unsigned char>((ascii_to_value[cipher[i*4]] << 2) + ((pos_of_char_1 & 0x30) >> 4));
        const auto pos_of_char_2 = ascii_to_value[cipher[i*4 + 2]];
        decipher[i*3 + 1] = static_cast<unsigned char>(((pos_of_char_1 & 0x0f) << 4) + ((pos_of_char_2 & 0x3c) >> 2));
        decipher[i*3 + 2] = static_cast<unsigned char>(((pos_of_char_2 & 0x03) << 6) + ascii_to_value[cipher[i*4 + 3]]);
    }
}

[[maybe_unused]]
constexpr static void apply_xor(unsigned char* cipher, const std::size_t size, const unsigned char* xor_key, const std::size_t xor_key_size)
{
    for(auto i = 0u; i < size; i++)
        cipher[i] ^= xor_key[i % xor_key_size];
}

// constexpr static const auto cipher = "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3"sv;
// constexpr const auto cipher = "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
// "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
// "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
// "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1"sv;

constexpr static const auto alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"sv;
constexpr static const auto key_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"sv;
// constexpr const char alphabet = "/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"sv;

// constexpr const std::string_view key = "VGhlR2lhbnRUaGVHaWFudFRoZUdpYW50"sv; // TheGiantTheGiantTheGiant
// constexpr const std::string_view key = "VGhlR2lhbnRUaGVHaWFudFRoZUdpYW50VGhlR2lhbnRUaGVHaWFudFRoZUdpYW50"sv; // TheGiantTheGiantTheGiantTheGiantTheGiantTheGiant
// constexpr const std::string_view key = "VEhFR0lBTlRUSEVHSUFOVFRIRUdJQU5UVEhFR0lBTlRUSEVHSUFOVFRIRUdJQU5U"sv; // THEGIANTTHEGIANTTHEGIANTTHEGIANTTHEGIANTTHEGIANT
// constexpr const std::string_view key = "THEGIANT"sv;
// constexpr const std::string_view key = "TheGiant"sv;
// constexpr const std::string_view key = "DerRiese"sv;
// constexpr const std::string_view key = "RGVyUmllc2VEZXJSaWVzZURlclJpZXNlRGVyUmllc2VEZXJSaWVzZURlclJpZXNl"sv;
// constexpr const std::string_view key = "05WYpdUZoRFduFWaHVGaURnbhl2RlhGV05WYpdUZoRFduFWaHVGaURnbhl2RlhGV"sv;
// constexpr const std::string_view key = "U5UQJdURIRFVOFUSHVESURlTBl0RFhEVU5UQJdURIRFVOFUSHVESURlTBl0RFhEV"sv;
// constexpr const std::string_view key = "DRMAXIS"sv;
// constexpr const std::string_view key = "RFJFRlBOU1dCQ09C"sv;
// constexpr const std::string_view key = "A"sv;

// constexpr const std::string_view xor_key = "TheGiant"sv;
// constexpr const std::string_view xor_key = "THEGIANT"sv;

constexpr static const auto ALPHABET_LENGTH = alphabet.length();
constexpr static const auto KEY_ALPHABET_LENGTH = key_alphabet.length();
constexpr static const auto CIPHER_LENGTH = cipher.length();
// constexpr static const auto KEY_LENGTH = key.length();
// constexpr static const auto XOR_KEY_LENGTH = xor_key.length();
constexpr static const auto DECIPHER_LENGTH = CIPHER_LENGTH * 3 / 4;

constexpr static unsigned char value(unsigned char* arr, unsigned char x) { return arr[x]; };
constexpr static unsigned char value(unsigned char* arr, char x) { return arr[static_cast<unsigned char>(x)]; };

void test_key(unsigned char* key, const std::size_t KEY_LENGTH)
{
    unsigned char decipher[DECIPHER_LENGTH]{ 0 };

    char new_alphabet[ALPHABET_LENGTH]{ 0 };
    char vigenere_cipher[CIPHER_LENGTH]{ 0 };
    char vigenere[ALPHABET_LENGTH][ALPHABET_LENGTH]{{ 0 }};

    for(auto k = 0u; k < 1; k++) {
        // Create new alphabet (rotate)
        for(auto i = 0u; i < ALPHABET_LENGTH; i++)
            new_alphabet[(i + k) % ALPHABET_LENGTH] = alphabet[i];

        // Optimization
        unsigned char ascii_to_value[256]{ 0 };
        for(unsigned char i = 0u; i < ALPHABET_LENGTH; i++)
            ascii_to_value[static_cast<unsigned char>(new_alphabet[i])] = i;

        // create vigenere from new alphabet
        for(auto i = 0u; i < ALPHABET_LENGTH; i++)
            for(auto j = 0u; j < ALPHABET_LENGTH; j++)
                vigenere[i][j] = new_alphabet[(i + j) % ALPHABET_LENGTH];

        // generate new cipher
        for(auto i = 0u; i < CIPHER_LENGTH; i++) {
            unsigned char x = i < KEY_LENGTH ? static_cast<unsigned char>(key[i]) : decipher[i - KEY_LENGTH];
            vigenere_cipher[i] = vigenere[value(ascii_to_value, cipher[i])][value(ascii_to_value, x)];
        }

        // std::println("Trying {}", std::string_view { vigenere_cipher, CIPHER_LENGTH });

        // try decoding it
        decode(decipher, reinterpret_cast<unsigned char*>(vigenere_cipher), CIPHER_LENGTH, ascii_to_value);
        // apply_xor(decipher, CIPHER_LENGTH, reinterpret_cast<const unsigned char*>(xor_key.begin()), XOR_KEY_LENGTH);

        bool printable{ true };
        for(auto i = 0u; i < DECIPHER_LENGTH; i++) {
            printable = std::isprint(decipher[i]) && printable;
            if (!printable)
                break;
        }

        // const auto entropy = calculate_entropy(decipher, DECIPHER_LENGTH);
        // if (printable || entropy < 5.5f) {
        //     std::println("entropy: {}", entropy);
        if (printable) {
            std::println("START: {}", std::string_view{ reinterpret_cast<const char*>(decipher), DECIPHER_LENGTH });
        }
    }
}

void make_key(char* key, size_t current_index, size_t size)
{
    for(auto i = 0u; i < KEY_ALPHABET_LENGTH; i++) {
        key[current_index] = key_alphabet[i];
        test_key(reinterpret_cast<unsigned char*>(key), size);
        if (current_index + 1 < size)
            make_key(key, current_index + 1, size);
    }
}

int main()
{
    char key[13]{ 0 };
    for(auto i = 0u; i < sizeof(key); i++)
        key[i] = key_alphabet[0];

    for(auto i = 1u; i < 13; i++)
    {
        std::println("Key length: {}", i);
        make_key(key, 0, i);
    }
}

