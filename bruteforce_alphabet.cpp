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
constexpr static auto plaintext_alphabet = cipher::base64::DEFAULT_ALPHABET;

thread_local std::uint64_t iteration = 0;
thread_local std::uint64_t max = 0;

static void test_alphabet_substitution(cipher::alphabet::alphabet_t<plaintext_alphabet.size()>& alphabet,
                                       std::array<bool, plaintext_alphabet.size()>& available_characters,
                                       cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()>& ascii_to_index,
                                       std::size_t ciphertext_index,
                                       char* plain,
                                       std::size_t plaintext_index)
{
    if (iteration++ % 10000000 == 0) [[unlikely]]
        std::println(stderr, "PLAIN: {:60} ALPHABET: {}", std::string_view{ plain, plaintext_index }, std::string_view{ alphabet.begin(), alphabet.end() });

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
        ascii_to_index[static_cast<std::uint8_t>(alphabet[i])] = static_cast<std::uint8_t>(-1);
        available_characters[i] = true;
        alphabet[i] = '_';
    };

    const auto alloc_and_move_forward = [&ascii_to_index, &available_characters, &alloc_place, &dealloc_place](const char c, const auto& pred) {
        if (ascii_to_index[static_cast<std::uint8_t>(c)] == static_cast<std::uint8_t>(-1)) {
            for(std::uint8_t i = 0u; i < available_characters.size(); i++) {
                if (!available_characters[i])
                    continue;
                alloc_place(i, c);
                pred();
                dealloc_place(i);
            }
        } else {
            pred();
        }
    };

    const auto move_forward = [&alloc_and_move_forward, &ascii_to_index](const char char_to_place, [[maybe_unused]] std::size_t index, const auto& pred) {
        alloc_and_move_forward(char_to_place, [&pred, &ascii_to_index, char_to_place]() {
            pred(plaintext_alphabet[ascii_to_index[static_cast<std::uint8_t>(char_to_place)]]);
        });
    };

    const auto pred4 = [plain, plaintext_index, ciphertext_index, &alphabet, &available_characters, &ascii_to_index](const char plaintext){
        plain[plaintext_index + 2] += plaintext;
        // std::println("PRED4: {}", std::string_view{ plain, plaintext_index + 3 });
        if (cipher::is_common_print(std::span{ plain + plaintext_index, 3 })) {
            test_alphabet_substitution(alphabet, available_characters, ascii_to_index, ciphertext_index + 4, plain, plaintext_index + 3);
        }
    };

    const auto pred3 = [plain, plaintext_index, &move_forward, ciphertext_index, &pred4](const char plaintext){
        plain[plaintext_index + 1] += static_cast<char>((plaintext & 0x3c) >> 2);
        plain[plaintext_index + 2] = static_cast<char>((plaintext & 0x3) << 6);
        // std::println("PRED3: {}", std::string_view{ plain, plaintext_index + 3 });
        if (!cipher::is_common_print(plain[plaintext_index + 1]))
            return;
        if (plain[plaintext_index + 2] & (1 << 7))
            return;

        const char chars_to_place = ciphertext[ciphertext_index + 3];
        move_forward(chars_to_place, 2, pred4);
    };

    const auto pred2 = [plain, plaintext_index, &move_forward, &pred3, ciphertext_index](const char plaintext){
        plain[plaintext_index + 0] += static_cast<char>((plaintext & 0x30) >> 4);
        plain[plaintext_index + 1] = static_cast<char>((plaintext & 0xf) << 4);
        // std::println("PRED2: {}", std::string_view{ plain, plaintext_index + 2 });
        if (plain[plaintext_index + 1] & (1 << 7))
            return;

        const char chars_to_place = ciphertext[ciphertext_index + 2];
        move_forward(chars_to_place, 2, pred3);
    };

    const auto pred1 = [plain, plaintext_index, &move_forward, &pred2, ciphertext_index](const char plaintext){
        plain[plaintext_index + 0] = static_cast<char>(plaintext << 2);
        // std::println("PRED1: {}", std::string_view{ plain, plaintext_index + 1 });
        if (!cipher::is_common_print(static_cast<char>(plaintext << 2)))
            return;

        const char chars_to_place = ciphertext[ciphertext_index + 1];
        move_forward(chars_to_place, 1, pred2);
    };

    const char chars_to_place = ciphertext[ciphertext_index];
    move_forward(chars_to_place, 0, pred1);

    plain[plaintext_index + 0] = '\0';
    plain[plaintext_index + 1] = '\0';
    plain[plaintext_index + 2] = '\0';

}

static void test_alphabet_vigenere(cipher::alphabet::alphabet_t<plaintext_alphabet.size()>& alphabet,
                                   std::array<bool, plaintext_alphabet.size()>& available_characters,
                                   cipher::alphabet::ascii_to_index_t<plaintext_alphabet.size()>& ascii_to_index,
                                   std::size_t ciphertext_index,
                                   char plain[ciphertext.size()],
                                   std::size_t plaintext_index)
{
    if (iteration++ % 1000000 == 0) [[unlikely]]
        std::println(stderr, "PLAIN: {:60} ALPHABET: {}", plain, std::string_view{ alphabet.begin(), alphabet.end() });

    if (ciphertext_index >= ciphertext.size()) [[unlikely]] {
        std::println("PLAIN: {:60} ALPHABET: {}", plain, std::string_view{ alphabet.begin(), alphabet.end() });
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
        if (ascii_to_index[static_cast<std::uint8_t>(c)] == static_cast<std::uint8_t>(-1)) {
            for(std::uint8_t i = 0u; i < available_characters.size(); i++) {
                if (!available_characters[i])
                    continue;
                alloc_place(i, c);
                pred();
                dealloc_place(i);
            }
        } else {
            pred();
        }
    };

    const auto move_forward = [&alloc_and_move_forward, &alloc_place, &dealloc_place, plain, &ascii_to_index, ciphertext_index, plaintext_index, &available_characters, &alphabet](const char chars_to_place[2], std::size_t index, const auto& pred) {
        alloc_and_move_forward(chars_to_place[0], [&](){
            alloc_and_move_forward(chars_to_place[1], [&](){
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
            });
        });
    };

    const auto pred4 = [plain, plaintext_index, ciphertext_index, &alphabet, &available_characters, &ascii_to_index](const char plaintext){
        plain[plaintext_index + 2] += plaintext;
        if (cipher::is_common_print(std::span{ plain + plaintext_index, 3 })) {
            test_alphabet_vigenere(alphabet, available_characters, ascii_to_index, ciphertext_index + 4, plain, plaintext_index + 3);
        }
    };

    const auto pred3 = [plain, plaintext_index, &move_forward, ciphertext_index, &pred4](const char plaintext){
        plain[plaintext_index + 1] += static_cast<char>((plaintext & 0x3c) >> 2);
        plain[plaintext_index + 2] = static_cast<char>((plaintext & 0x3) << 6);
        if (!cipher::is_common_print(plain[plaintext_index + 1]))
            return;
        if (plain[plaintext_index + 2] & (1 << 7))
            return;

        const char chars_to_place[] = { ciphertext[ciphertext_index + 3], key[(ciphertext_index + 3) % key.size()] };
        move_forward(chars_to_place, 2, pred4);
    };

    const auto pred2 = [plain, plaintext_index, &move_forward, &pred3, ciphertext_index](const char plaintext){
        plain[plaintext_index + 0] += static_cast<char>((plaintext & 0x30) >> 4);
        plain[plaintext_index + 1] = static_cast<char>((plaintext & 0xf) << 4);
        if (plain[plaintext_index + 1] & (1 << 7))
            return;

        const char chars_to_place[] = { ciphertext[ciphertext_index + 2], key[(ciphertext_index + 2) % key.size()] };
        move_forward(chars_to_place, 2, pred3);
    };

    const auto pred1 = [plain, plaintext_index, &move_forward, &pred2, ciphertext_index](const char plaintext){
        plain[plaintext_index + 0] = static_cast<char>(plaintext << 2);
        if (!cipher::is_common_print(static_cast<char>(plaintext << 2)))
            return;

        const char chars_to_place[] = { ciphertext[ciphertext_index + 1], key[(ciphertext_index + 1) % key.size()] };
        move_forward(chars_to_place, 1, pred2);
    };

    const char chars_to_place[] = { ciphertext[ciphertext_index], key[(ciphertext_index) % key.size()] };
    move_forward(chars_to_place, 0, pred1);
    plain[plaintext_index + 0] = '\0';
    plain[plaintext_index + 1] = '\0';
    plain[plaintext_index + 2] = '\0';
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

static void bruteforce_alphabet()
{
    // std::println("{}", std::string_view{ plaintext_alphabet.begin(), plaintext_alphabet.end() });
    // #pragma omp parallel for
    for(auto i = 0u; i < plaintext_alphabet.size(); i++) {
        // auto [alphabet, ascii_to_index, available_characters] = create_starting_configuration(std::string_view{ plaintext_alphabet.begin() + i, 1 });
        auto [alphabet, ascii_to_index, available_characters] = create_starting_configuration("TheGiant");

        thread_local char plaintext[ciphertext.size()]{ 0 };
        test_alphabet_substitution(alphabet, available_characters, ascii_to_index, 0, plaintext, 0);
    }

    std::println("done?");

}

int main()
{
    bruteforce_alphabet();
    return 0;
}

