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
    constexpr static auto encrypt_vigenere(const cipher::buffer_t<len, charT>& buffer)
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
    constexpr static auto decrypt_vigenere(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len, charT>();
        cipher::vigenere::decode<false>(std::span{ ciphertext },
                                        std::span{ buffer },
                                        std::span{ key },
                                        vigenere_decoding_table,
                                        vigenere_ascii_to_index);
        return ciphertext;
    }

    constexpr static auto test1 = encrypt_vigenere(cipher::buffer("DEFENDTHEEASTWALLOFTHECASTLE"));
    static_assert(cipher::to_string(test1) == "ISWXVIBJEXIGGBOCEWKBJEVIGGQS"sv, cipher::to_string(test1));

    constexpr static auto test2 = decrypt_vigenere(cipher::buffer("ISWXVIBJEXIGGBOCEWKBJEVIGGQS"));
    static_assert(cipher::to_string(test2) == "DEFENDTHEEASTWALLOFTHECASTLE"sv, cipher::to_string(test2));

    template<std::size_t len, typename charT>
    constexpr static auto encrypt_autokey(const cipher::buffer_t<len, charT>& buffer)
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
    constexpr static auto decrypt_autokey(const cipher::buffer_t<len, charT>& buffer)
    {
        auto ciphertext = cipher::empty_buffer<len, charT>();
        cipher::vigenere::decode<true>(std::span{ ciphertext },
                                        std::span{ buffer },
                                        std::span{ key },
                                        vigenere_decoding_table,
                                        vigenere_ascii_to_index);
        return ciphertext;
    }

    constexpr static auto test3 = encrypt_autokey(cipher::buffer("DEFENDTHEEASTWALLOFTHECASTLE"));
    static_assert(cipher::to_string(test3) == "ISWXVIBJEXIGGZEQPBIMOIGAKMHE"sv, cipher::to_string(test3));

    constexpr static auto test4 = decrypt_autokey(cipher::buffer("ISWXVIBJEXIGGZEQPBIMOIGAKMHE"));
    static_assert(cipher::to_string(test4) == "DEFENDTHEEASTWALLOFTHECASTLE"sv, cipher::to_string(test4));

}

namespace substitution
{
    
}

}
