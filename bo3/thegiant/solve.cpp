#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <vector>

constexpr const auto cipher = "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
"fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
"dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
"JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1";

// constexpr const auto cipher = "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3";

const auto cipher_len = std::string_view{ cipher }.length();
char cipher2[cipher_len + 1]{ 0 };
unsigned char decipher[cipher_len * 3 / 4]{ 0 };

float calculate_entropy() {
    unsigned char counted_bytes[256]{ 0 };
    std::memset(counted_bytes, 0, 256);

    for (int j = 0; j < sizeof(decipher); j++) {
        const unsigned char count = static_cast<unsigned char> (decipher[j]);
        counted_bytes[count]++;
    }

    double entropy = 0.;
    double temp;
    for (int i = 0; i < 256; i++) {
        temp = static_cast<float>(counted_bytes[i]) / sizeof(decipher);

        if (temp > 0.)
            entropy += temp * fabs(log2(temp));
    }

    return entropy;
}

unsigned char ascii_to_value[256]{};
unsigned char value(unsigned char c) { return ascii_to_value[c]; }

inline void decode() {
    size_t pos = 0;
    size_t decipher_pos = 0;

    while (pos < cipher_len) {
        const auto pos_of_char_1 = value(cipher2[pos + 1]);
        decipher[decipher_pos] = (value(cipher2[pos]) << 2) + ((pos_of_char_1 & 0x30) >> 4);

        if (pos + 2 < cipher_len) {
            const auto pos_of_char_2 = value(cipher2[pos + 2]);
            decipher[decipher_pos + 1] = ((pos_of_char_1 & 0x0f) << 4) + ((pos_of_char_2 & 0x3c) >> 2);

            if (pos + 3 < cipher_len)
                decipher[decipher_pos + 2] = ((pos_of_char_2 & 0x03) << 6) + value(cipher2[pos + 3]);
        }

        pos += 4;
        decipher_pos += 3;
    }
}

#define ALPHABET_LENGTH 64

constexpr const unsigned char alphabet[ALPHABET_LENGTH+1] { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };
// constexpr const char alphabet[65]{ "/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA" };
// constexpr const char alphabet[65]{ "TheGiantTheGiantTheGiantTheGiantTheGiantTheGiantTheGiantTheGia+/" };

// constexpr const unsigned char key[] { "VGhlR2lhbnRUaGVHaWFudFRoZUdpYW50VGhlR2lhbnRUaGVHaWFudFRoZUdpYW50" }; // TheGiantTheGiantTheGiantTheGiantTheGiantTheGiant
// constexpr const unsigned char key[] { "VEhFR0lBTlRUSEVHSUFOVFRIRUdJQU5UVEhFR0lBTlRUSEVHSUFOVFRIRUdJQU5U" }; // THEGIANTTHEGIANTTHEGIANTTHEGIANTTHEGIANTTHEGIANT
// constexpr const unsigned char key[] { "THEGIANT" };
// constexpr const unsigned char key[] { "TheGiant" };
// constexpr const unsigned char key[] { "DerRiese" };
// constexpr const unsigned char key[] { "RGVyUmllc2VEZXJSaWVzZURlclJpZXNlRGVyUmllc2VEZXJSaWVzZURlclJpZXNl" };
// constexpr const unsigned char key[] { "05WYpdUZoRFduFWaHVGaURnbhl2RlhGV05WYpdUZoRFduFWaHVGaURnbhl2RlhGV" };
// constexpr const unsigned char key[] { "U5UQJdURIRFVOFUSHVESURlTBl0RFhEVU5UQJdURIRFVOFUSHVESURlTBl0RFhEV" };
// constexpr const unsigned char key[] { "DREFPNSWBCOB" };
constexpr const unsigned char key[] { "RFJFRlBOU1dCQ09C" };

char new_alphabet[ALPHABET_LENGTH]{ 0 };
char vigenere[ALPHABET_LENGTH][ALPHABET_LENGTH]{ 0 };


int main()
{
    std::printf("%s\n", cipher);
    for(int k = 0; k < ALPHABET_LENGTH; k++) {

        // Create new alphabet (rotate)
        for(int i = 0; i < ALPHABET_LENGTH; i++)
            new_alphabet[(i + k) % ALPHABET_LENGTH] = alphabet[i];

        // Optimization
        std::memset(ascii_to_value, 0, 256);
        for(int i = 0; i < ALPHABET_LENGTH; i++)
            ascii_to_value[new_alphabet[i]] = i;

        // create vigenere from new alphabet
        for(int i = 0; i < ALPHABET_LENGTH; i++)
            for(int j = 0; j < ALPHABET_LENGTH; j++)
                vigenere[i][j] = new_alphabet[(i + j) % ALPHABET_LENGTH];

        // generate new cipher
        for(int i = 0; i < cipher_len; i++)
            cipher2[i] = vigenere[ascii_to_value[cipher[i]]][ascii_to_value[key[i % sizeof(key) - 1]]];

        // printf("Trying %s\n", cipher2);

        // try decoding it
        decode();

        bool printable{true};
        for(int i = 0; i < sizeof(decipher); i++) {
            printable = std::isprint(decipher[i]) && printable;
            if (!printable)
                break;
        }

        const auto entropy = calculate_entropy();
        std::printf("entropy: %f\n", entropy);
        if (printable || entropy < 5.5f) {
            std::printf("%s", decipher);
            std::puts("");
        }
    }
}

