#include <array>
#include <cstdio>
#include <print>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/vigenere.hpp>

// constexpr static const auto ciphertext = cipher::buffer(
//     "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3");
constexpr static const auto ciphertext = cipher::buffer(
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");
constexpr const auto key = cipher::buffer("TheGiant");

constexpr static auto plaintext_alphabet = cipher::alphabet::create("/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA");
constexpr static auto plaintext_ascii_to_value = cipher::alphabet::create_ascii_to_index_array(plaintext_alphabet);

// constexpr static auto common_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRTSUVWXYZabcdefghijklmnopqrstuvwxyz1234567890.,");
constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
// constexpr static auto common_alphabet = cipher::alphabet::create("0123456789 ");

thread_local std::uint64_t iteration = 0;
thread_local std::uint64_t max = 0;

static void test_alphabet_substitution(cipher::alphabet::alphabet_t<plaintext_alphabet.size()>& alphabet,
                                       std::array<bool, plaintext_alphabet.size()>& available_characters,
                                       cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()>& ascii_to_index,
                                       std::size_t ciphertext_index,
                                       char* plain,
                                       std::size_t plaintext_index,
                                       char* base64_plaintext)
{
    if (iteration++ % 100000000 == 0 && plaintext_index > 3) [[unlikely]]
        std::println(stderr, "PLAIN: {:60} ALPHABET: {}", std::string_view{ plain, plaintext_index }, std::string_view{ alphabet.begin(), alphabet.end() });

    // cipher::buffer_t<4, char> buffer;
    // for(auto i = 0u; i < plaintext_index / 4; i++) {
    //     cipher::base64::decode(std::span{ buffer },
    //                            std::span{ plain + i * 4, 4 });
    //     if (!cipher::is_print(std::span{ buffer }))
    //         return;
    // }

    if (ciphertext_index >= ciphertext.size()) [[unlikely]] {
        std::println("FOUND PLAIN: {:60} ALPHABET: {}", plain, std::string_view{ alphabet.begin(), alphabet.end() });
        return;
    }

    const auto alloc_place = [&available_characters, &alphabet, &ascii_to_index](std::uint8_t i, char c) {
        available_characters[i] = false;
        alphabet[i] = c;
        ascii_to_index[static_cast<std::uint8_t>(c)] = i;
    };

    const auto dealloc_place = [&ascii_to_index, &available_characters, &alphabet](std::uint8_t i) {
        ascii_to_index[(uint8_t)(alphabet[i])] = static_cast<std::uint8_t>(-1);
        available_characters[i] = true;
        alphabet[i] = '_';
    };

    const auto alloc_and_move_forward = [&ascii_to_index, &available_characters, &alloc_place, &dealloc_place](const char c, const auto& pred) {
        if (ascii_to_index[static_cast<std::uint8_t>(c)] != static_cast<std::uint8_t>(-1)) {
            pred();
            return;
        }

        for(std::uint8_t i = 0u; i < available_characters.size(); i++) {
            if (!available_characters[i])
                continue;
            alloc_place(i, c);
            pred();
            dealloc_place(i);
        }
    };

    const auto move_forward = [&alloc_and_move_forward, &ascii_to_index](const char char_to_place, [[maybe_unused]] std::size_t index, const auto& pred) {
        const auto translate_to_plaintext = [&pred, &ascii_to_index, char_to_place]() {
            pred(plaintext_alphabet[ascii_to_index[static_cast<std::uint8_t>(char_to_place)]]);
        };
        alloc_and_move_forward(char_to_place, translate_to_plaintext);
    };

    const auto base64_decode_fourth_char = [base64_plaintext, plain, plaintext_index, ciphertext_index, &alphabet, &available_characters, &ascii_to_index](const char plain_base64_char){
        base64_plaintext[ciphertext_index + 3] = plain_base64_char;

        const auto value = plaintext_ascii_to_value[static_cast<std::uint8_t>(plain_base64_char)];
        const auto old_value = plain[plaintext_index + 2];
        plain[plaintext_index + 2] = static_cast<char>(old_value + value);

        if (std::string_view{ plain, plaintext_index + 3 }.starts_with(" ")) { // should really only do this once but whatever
            plain[plaintext_index + 2] = old_value;
            base64_plaintext[ciphertext_index + 3] = 0;
            return;
        }

        // if (cipher::is_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(std::span{ plain + plaintext_index, 3 })) {
        // if (cipher::is_in_alphabet<common_alphabet>(std::span{ plain + plaintext_index, 3 })) {
        if (cipher::is_print(std::span{ plain + plaintext_index, 3 })) {
        // if (cipher::is_common_print(std::span{ plain + plaintext_index, 3 })) {
            test_alphabet_substitution(alphabet, available_characters, ascii_to_index, ciphertext_index + 4, plain, plaintext_index + 3, base64_plaintext);
        }
        plain[plaintext_index + 2] = old_value;
        base64_plaintext[ciphertext_index + 3] = 0;
    };

    const auto base64_decode_third_char = [base64_plaintext, plain, plaintext_index, &move_forward, ciphertext_index, &base64_decode_fourth_char](const char plain_base64_char){
        base64_plaintext[ciphertext_index + 2] = plain_base64_char;

        const auto value = plaintext_ascii_to_value[static_cast<std::uint8_t>(plain_base64_char)];
        const auto old_value = plain[plaintext_index + 1];
        plain[plaintext_index + 1] = static_cast<char>(old_value + ((value & 0x3c) >> 2));
        plain[plaintext_index + 2] = static_cast<char>((value & 0x03) << 6);

        if (!cipher::is_print(plain[plaintext_index + 1]) || plain[plaintext_index + 2] & (1 << 7)) {
            plain[plaintext_index + 1] = old_value;
            plain[plaintext_index + 2] = 0;
            base64_plaintext[ciphertext_index + 2] = 0;
            return;
        }

        const char chars_to_place = ciphertext[ciphertext_index + 3];
        move_forward(chars_to_place, 3, base64_decode_fourth_char);

        plain[plaintext_index + 1] = old_value;
        plain[plaintext_index + 2] = 0;
        base64_plaintext[ciphertext_index + 2] = 0;
    };

    const auto base64_decode_second_char = [base64_plaintext, plain, plaintext_index, &move_forward, &base64_decode_third_char, ciphertext_index](const char plain_base64_char){
        base64_plaintext[ciphertext_index + 1] = plain_base64_char;

        const auto value = plaintext_ascii_to_value[static_cast<std::uint8_t>(plain_base64_char)];
        const auto old_value = plain[plaintext_index + 0];
        plain[plaintext_index + 0] = static_cast<char>(old_value + ((value & 0x30) >> 4));
        plain[plaintext_index + 1] = static_cast<char>((value & 0x0f) << 4);

        if (plain[plaintext_index + 1] & (1 << 7)) {
            plain[plaintext_index + 0] = old_value;
            plain[plaintext_index + 1] = 0;
            base64_plaintext[ciphertext_index + 1] = 0;
            return;
        }

        const char chars_to_place = ciphertext[ciphertext_index + 2];
        move_forward(chars_to_place, 2, base64_decode_third_char);

        plain[plaintext_index + 0] = old_value;
        plain[plaintext_index + 1] = 0;
        base64_plaintext[ciphertext_index + 1] = 0;
    };

    const auto base64_decode_first_char = [base64_plaintext, plain, plaintext_index, &move_forward, &base64_decode_second_char, ciphertext_index](const char plain_base64_char){
        base64_plaintext[ciphertext_index + 0] = plain_base64_char;

        const auto value = plaintext_ascii_to_value[static_cast<std::uint8_t>(plain_base64_char)];
        plain[plaintext_index + 0] = static_cast<char>(value << 2);

        if (!cipher::is_print(plain[plaintext_index])) {
            plain[plaintext_index + 0] = 0;
            base64_plaintext[ciphertext_index + 0] = 0;
            return;
        }

        const char chars_to_place = ciphertext[ciphertext_index + 1];
        move_forward(chars_to_place, 1, base64_decode_second_char);

        plain[plaintext_index + 0] = 0;
        base64_plaintext[ciphertext_index + 0] = 0;
    };

    const char chars_to_place = ciphertext[ciphertext_index];
    move_forward(chars_to_place, 0, base64_decode_first_char);
}

static void test_alphabet_vigenere(cipher::alphabet::alphabet_t<plaintext_alphabet.size()>& alphabet,
                                   std::array<bool, plaintext_alphabet.size()>& available_characters,
                                   cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()>& ascii_to_index,
                                   std::size_t ciphertext_index,
                                   char* plain,
                                   std::size_t plaintext_index)
{
    if (iteration++ % 100000000 == 0) [[unlikely]]
        std::println(stderr, "PLAIN: {:64} ALPHABET: {}", plain, std::string_view{ alphabet.begin(), alphabet.end() });

    if (ciphertext_index >= ciphertext.size()) [[unlikely]] {
        std::println("FOUND PLAIN: {:64} ALPHABET: {}", plain, std::string_view{ alphabet.begin(), alphabet.end() });
        return;
    }

    const auto alloc_place = [&available_characters, &alphabet, &ascii_to_index](std::uint8_t i, char c) {
        available_characters[i] = false;
        alphabet[i] = c;
        ascii_to_index[static_cast<std::uint8_t>(c)] = i;
    };

    const auto dealloc_place = [&ascii_to_index, &available_characters, &alphabet](std::uint8_t i) {
        ascii_to_index[static_cast<std::uint8_t>(alphabet[i])] = static_cast<std::uint8_t>(-1);
        available_characters[i] = true;
        alphabet[i] = '_';
    };

    const auto alloc_and_move_forward = [&ascii_to_index, &available_characters, &alloc_place, &dealloc_place](const char c, const auto& pred) {
        if (ascii_to_index[static_cast<std::uint8_t>(c)] != static_cast<std::uint8_t>(-1)) {
            pred();
            return;
        }

        for(std::uint8_t i = 0u; i < available_characters.size(); i++) {
            if (!available_characters[i])
                continue;
            alloc_place(i, c);
            pred();
            dealloc_place(i);
        }
    };

    const auto move_forward = [&alloc_and_move_forward, &alloc_place, &dealloc_place, &ascii_to_index, ciphertext_index, &available_characters, &alphabet](const std::size_t index, const auto& pred) {
        const auto source_char = ciphertext[ciphertext_index + index];
        const auto key_char = key[(ciphertext_index + index) % key.size()];
        alloc_and_move_forward(source_char, [&, key_char]() {
            alloc_and_move_forward(key_char, [&, source_char]() {
                const auto index = cipher::vigenere::alphabet_index<false, 64>(ascii_to_index, source_char, key_char);
                if (!available_characters[index]) {
                    pred(alphabet[index]);
                    return;
                }
                for(const char c : plaintext_alphabet) {
                    if (ascii_to_index[static_cast<std::uint8_t>(c)] != static_cast<std::uint8_t>(-1))
                        continue;
                    alloc_place(index, c);
                    pred(c);
                    dealloc_place(index);
                }
            });
        });
    };

    const auto base64_decode_fourth_char = [plain, plaintext_index, ciphertext_index, &alphabet, &available_characters, &ascii_to_index](const char plain_base64_char){
        const auto value = plaintext_ascii_to_value[static_cast<std::uint8_t>(plain_base64_char)];
        const auto old_value = plain[plaintext_index + 2];
        plain[plaintext_index + 2] = static_cast<char>(old_value + value);

        // if (cipher::is_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(std::span{ plain + plaintext_index, 3 })) {
        if (cipher::is_in_alphabet<common_alphabet>(std::span{ plain + plaintext_index, 3 })) {
        // if (cipher::is_print(std::span{ plain + plaintext_index, 3 })) {
        // if (cipher::is_common_print(std::span{ plain + plaintext_index, 3 })) {
            test_alphabet_vigenere(alphabet, available_characters, ascii_to_index, ciphertext_index + 4, plain, plaintext_index + 3);
        }
        plain[plaintext_index + 2] = old_value;
    };

    const auto base64_decode_third_char = [plain, plaintext_index, &move_forward, &base64_decode_fourth_char](const char plain_base64_char){
        const auto value = plaintext_ascii_to_value[static_cast<std::uint8_t>(plain_base64_char)];
        const auto old_value = plain[plaintext_index + 1];
        plain[plaintext_index + 1] = static_cast<char>(old_value + ((value & 0x3c) >> 2));
        plain[plaintext_index + 2] = static_cast<char>((value & 0x03) << 6);

        if (!cipher::char_is_in_alphabet<common_alphabet>(plain[plaintext_index + 1]) || plain[plaintext_index + 2] & (1 << 7)) {
            plain[plaintext_index + 1] = old_value;
            plain[plaintext_index + 2] = 0;
            return;
        }

        move_forward(3, base64_decode_fourth_char);

        plain[plaintext_index + 1] = old_value;
        plain[plaintext_index + 2] = 0;
    };

    const auto base64_decode_second_char = [plain, plaintext_index, &move_forward, &base64_decode_third_char](const char plain_base64_char){
        const auto value = plaintext_ascii_to_value[static_cast<std::uint8_t>(plain_base64_char)];
        const auto old_value = plain[plaintext_index + 0];
        plain[plaintext_index + 0] = static_cast<char>(old_value + ((value & 0x30) >> 4));
        plain[plaintext_index + 1] = static_cast<char>((value & 0x0f) << 4);

        if (!cipher::char_is_in_alphabet<common_alphabet>(plain[plaintext_index + 0]) || plain[0] == ' ' || plain[0] == '!' || plain[plaintext_index + 1] & (1 << 7)) {
            plain[plaintext_index + 0] = old_value;
            plain[plaintext_index + 1] = 0;
            return;
        }

        move_forward(2, base64_decode_third_char);

        plain[plaintext_index + 0] = old_value;
        plain[plaintext_index + 1] = 0;
    };

    const auto base64_decode_first_char = [plain, plaintext_index, &move_forward, &base64_decode_second_char](const char plain_base64_char){
        const auto value = plaintext_ascii_to_value[static_cast<std::uint8_t>(plain_base64_char)];
        plain[plaintext_index + 0] = static_cast<char>(value << 2);

        if (!cipher::is_print(plain[plaintext_index])) {
            plain[plaintext_index + 0] = 0;
            return;
        }

        move_forward(1, base64_decode_second_char);

        plain[plaintext_index + 0] = 0;
    };

    move_forward(0, base64_decode_first_char);
}

constexpr static std::tuple<cipher::alphabet::alphabet_t<plaintext_alphabet.size()>, cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()>, std::array<bool, plaintext_alphabet.size()>> create_starting_configuration(const std::string_view config)
{
    cipher::alphabet::alphabet_t<plaintext_alphabet.size()> cipher_alphabet{};
    cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()> cipher_ascii_to_index{};
    std::array<bool, plaintext_alphabet.size()> available_characters{};

    for(auto& b : available_characters)
        b = true;
    for(auto& b : cipher_ascii_to_index)
        b = static_cast<std::uint8_t>(-1);
    for(auto& b : cipher_alphabet)
        b = '_';

    for(std::uint8_t i = 0u; i < config.length(); i++) {
        available_characters[i] = false;
        cipher_ascii_to_index[static_cast<std::uint8_t>(config[i])] = i;
        cipher_alphabet[i] = config[i];
    }

    return { cipher_alphabet, cipher_ascii_to_index, available_characters };
}

constexpr static void add_to_configuration(cipher::alphabet::alphabet_t<plaintext_alphabet.size()>& alphabet, cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()>& ascii_to_index, std::array<bool, plaintext_alphabet.size()>& available_characters, const std::string_view config)
{
    for(std::uint8_t i = 0u; i < config.length(); i++) {
        for(std::uint8_t j = 0u; j < available_characters.size(); j++) {
            if (!available_characters[j])
                continue;
            available_characters[j] = false;
            ascii_to_index[static_cast<std::uint8_t>(config[i])] = j;
            alphabet[j] = config[i];
            break;
        }
    }
}

static void bruteforce_alphabet()
{
    #pragma omp parallel for
    for(auto i = 0u; i < plaintext_alphabet.size(); i++) {
        auto [alphabet, ascii_to_index, available_characters] = create_starting_configuration("");
        add_to_configuration(alphabet, ascii_to_index, available_characters, { plaintext_alphabet.begin() + i, 1 });

        char plaintext[ciphertext.size()]{ 0 };
        test_alphabet_vigenere(alphabet, available_characters, ascii_to_index, 0, plaintext, 0);
        std::println("EXIT {}", plaintext_alphabet[i]);
    }

    std::println("done?");
}

int main()
{
    bruteforce_alphabet();
    return 0;
}

