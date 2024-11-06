#include <string_view>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/entropy.hpp>
#include <cipher/vigenere.hpp>
#include <cipher/xor.hpp>

using namespace std::string_view_literals;

namespace test
{

namespace vigenere
{

    constexpr static const auto vigenere_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    constexpr static const auto vigenere_ascii_to_index = cipher::alphabet::create_ascii_to_index_array(vigenere_alphabet);
    constexpr static const auto vigenere_decoding_table = cipher::vigenere::create_decode_table(vigenere_alphabet, vigenere_ascii_to_index);
    constexpr static const auto vigenere_encoding_table = cipher::vigenere::create_table(vigenere_alphabet);

    constexpr static auto key = cipher::buffer("FORTIFICATION");

    template<std::size_t len, typename charT>
    constexpr static auto encrypt_vigenere_table(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len, charT>();
        cipher::vigenere::encode<false>(std::span{ ciphertext },
                                        std::span{ buffer },
                                        std::span{ key },
                                        vigenere_encoding_table,
                                        vigenere_ascii_to_index);
        return ciphertext;
    }

    template<std::size_t len, typename charT>
    constexpr static auto encrypt_vigenere(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len, charT>();
        cipher::vigenere::encode<false>(std::span{ ciphertext },
                                        std::span{ buffer },
                                        std::span{ key },
                                        vigenere_alphabet,
                                        vigenere_ascii_to_index);
        return ciphertext;
    }

    template<std::size_t len, typename charT>
    constexpr static auto decrypt_vigenere_table(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len, charT>();
        cipher::vigenere::decode<false>(std::span{ ciphertext },
                                        std::span{ buffer },
                                        std::span{ key },
                                        vigenere_decoding_table,
                                        vigenere_ascii_to_index);
        return ciphertext;
    }

    template<std::size_t len, typename charT>
    constexpr static auto decrypt_vigenere(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len, charT>();
        cipher::vigenere::decode<false>(std::span{ ciphertext },
                                        std::span{ buffer },
                                        std::span{ key },
                                        vigenere_alphabet,
                                        vigenere_ascii_to_index);
        return ciphertext;
    }

    constexpr static auto test_vigenere_table_1 = encrypt_vigenere_table(cipher::buffer("DEFENDTHEEASTWALLOFTHECASTLE"));
    static_assert(cipher::to_string(test_vigenere_table_1) == "ISWXVIBJEXIGGBOCEWKBJEVIGGQS"sv, cipher::to_string(test_vigenere_table_1));

    constexpr static auto test_vigenere_table_2 = decrypt_vigenere_table(cipher::buffer("ISWXVIBJEXIGGBOCEWKBJEVIGGQS"));
    static_assert(cipher::to_string(test_vigenere_table_2) == "DEFENDTHEEASTWALLOFTHECASTLE"sv, cipher::to_string(test_vigenere_table_2));

    constexpr static auto test_vigenere_1 = encrypt_vigenere(cipher::buffer("DEFENDTHEEASTWALLOFTHECASTLE"));
    static_assert(cipher::to_string(test_vigenere_1) == "ISWXVIBJEXIGGBOCEWKBJEVIGGQS"sv, cipher::to_string(test_vigenere_1));

    constexpr static auto test_vigenere_2 = decrypt_vigenere(cipher::buffer("ISWXVIBJEXIGGBOCEWKBJEVIGGQS"));
    static_assert(cipher::to_string(test_vigenere_2) == "DEFENDTHEEASTWALLOFTHECASTLE"sv, cipher::to_string(test_vigenere_2));

    template<std::size_t len, typename charT>
    constexpr static auto encrypt_autokey_table(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len, charT>();
        cipher::vigenere::encode<true>(std::span{ ciphertext },
                                        std::span{ buffer },
                                        std::span{ key },
                                        vigenere_encoding_table,
                                        vigenere_ascii_to_index);
        return ciphertext;
    }

    template<std::size_t len, typename charT>
    constexpr static auto decrypt_autokey_table(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len, charT>();
        cipher::vigenere::decode<true>(std::span{ ciphertext },
                                        std::span{ buffer },
                                        std::span{ key },
                                        vigenere_decoding_table,
                                        vigenere_ascii_to_index);
        return ciphertext;
    }

    constexpr static auto test_autokey_table_1 = encrypt_autokey_table(cipher::buffer("DEFENDTHEEASTWALLOFTHECASTLE"));
    static_assert(cipher::to_string(test_autokey_table_1) == "ISWXVIBJEXIGGZEQPBIMOIGAKMHE"sv, cipher::to_string(test_autokey_table_1));

    constexpr static auto test_autokey_table_2 = decrypt_autokey_table(cipher::buffer("ISWXVIBJEXIGGZEQPBIMOIGAKMHE"));
    static_assert(cipher::to_string(test_autokey_table_2) == "DEFENDTHEEASTWALLOFTHECASTLE"sv, cipher::to_string(test_autokey_table_2));

    template<std::size_t len, typename charT>
    constexpr static auto encrypt_autokey(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len, charT>();
        cipher::vigenere::encode<true>(std::span{ ciphertext },
                                        std::span{ buffer },
                                        std::span{ key },
                                        vigenere_alphabet,
                                        vigenere_ascii_to_index);
        return ciphertext;
    }

    template<std::size_t len, typename charT>
    constexpr static auto decrypt_autokey(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len, charT>();
        cipher::vigenere::decode<true>(std::span{ ciphertext },
                                        std::span{ buffer },
                                        std::span{ key },
                                        vigenere_alphabet,
                                        vigenere_ascii_to_index);
        return ciphertext;
    }

    constexpr static auto test_autokey_1 = encrypt_autokey(cipher::buffer("DEFENDTHEEASTWALLOFTHECASTLE"));
    static_assert(cipher::to_string(test_autokey_1) == "ISWXVIBJEXIGGZEQPBIMOIGAKMHE"sv, cipher::to_string(test_autokey_1));

    constexpr static auto test_autokey_2 = decrypt_autokey(cipher::buffer("ISWXVIBJEXIGGZEQPBIMOIGAKMHE"));
    static_assert(cipher::to_string(test_autokey_2) == "DEFENDTHEEASTWALLOFTHECASTLE"sv, cipher::to_string(test_autokey_2));
}

namespace substitution
{
    
}

namespace base64
{
    template<std::size_t len, typename charT>
    constexpr static auto decode_b64(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len*3/4, charT>();
        cipher::base64::decode(std::span{ ciphertext },
                               std::span{ buffer });
        return ciphertext;
    }

    constexpr static auto test_base64_1 = decode_b64(cipher::buffer("SGVsbG8gV29ybGRk"));
    static_assert(cipher::to_string(test_base64_1) == "Hello Worldd"sv, cipher::to_string(test_base64_1));

}

}
