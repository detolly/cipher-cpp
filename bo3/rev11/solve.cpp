
#include <cstdio>
#include <cstring>
#include <string_view>

using namespace std::string_view_literals;

constexpr const auto cipher = "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3"sv;
unsigned char decipher[cipher.length()]{ 0 };

unsigned char ascii_to_value[256]{};

inline unsigned char value(unsigned char c) { return ascii_to_value[c]; }

void decode() {
    constexpr auto length_of_string = cipher.length();
    size_t pos = 0;

    while (pos < length_of_string) {
        const auto pos_of_char_1 = value(cipher.at(pos+1));
        decipher[pos] = (value(cipher[pos+0]) << 2) + ((pos_of_char_1 & 0x30) >> 4);

        if ((pos + 2 < length_of_string) && cipher[pos+2] != '=' && cipher[pos+2] != '.') {
            const auto pos_of_char_2 = value(cipher[pos+2]);
            decipher[pos + 1] = ((pos_of_char_1 & 0x0f) << 4) + ((pos_of_char_2 & 0x3c) >> 2);

            if ((pos + 3 < length_of_string ) && cipher[pos+3] != '=' && cipher[pos+3] != '.')
                decipher[pos + 2] = ((pos_of_char_2 & 0x03) << 6) + value(cipher[pos + 3]);
        }

       pos += 4;
    }
}

void create_alphabet(const char a[64])
{
    for(int i = 0; i < 64; i++) {
        ascii_to_value[a[i]] = i;
    }
}

int main()
{
    create_alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    decode();

    for(int i = 0; i < sizeof(decipher); i++)
        std::printf("%02x", decipher[i]);

    std::puts("");
}
