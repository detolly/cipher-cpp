#include <iostream>
#include <print>
#include <string_view>

#include <argparse.hpp>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/vigenere.hpp>

int main(int argc, const char* argv[])
{
    argparse::ArgumentParser parser("vigenere");

    parser.add_argument("-a", "--alphabet")
        .default_value(std::string(cipher::base64::DEFAULT_ALPHABET.begin(), cipher::base64::DEFAULT_ALPHABET.size()));
    parser.add_argument("-d", "--decode").flag().default_value(false);
    parser.add_argument("--autokey").flag().default_value(false);
    parser.add_argument("-k", "--key").required();
    parser.add_argument("--debug").flag().default_value(false);
    parser.add_argument("source").required();

    try {
        parser.parse_args(argc, argv);
    } catch(const std::exception& e) {
        std::println(stderr, "{}", e.what());
        std::cerr << parser;
        std::exit(1);
    }

    const auto debug = parser.get<bool>("--debug");
    auto source = parser.get<std::string>("source");
    if (debug)
        std::println(stderr, "SOURCE: _{}_", source);

    if (source == "-") {
        source.clear();
        std::string temp;
        while (std::cin >> temp) source += temp;
        if (debug)
            std::println(stderr, "SOURCE: _{}_", source);
    }

    std::string target;
    target.resize(source.length());

    const auto decode = parser.get<bool>("--decode");
    if (debug)
        std::println(stderr, "DECODE: _{}_", decode);

    const auto autokey = parser.get<bool>("--autokey");
    if (debug)
        std::println(stderr, "AUTOKEY: _{}_", autokey);

    const auto alphabet = parser.get<std::string>("--alphabet");
    if (debug)
        std::println(stderr, "ALPHABET: _{}_", alphabet);

    const auto key = parser.get<std::string>("--key");
    if (debug)
        std::println(stderr, "KEY: _{}_", key);

    const auto ascii_to_index = cipher::alphabet::create_ascii_to_index_array(std::span{ alphabet });

    if (decode) {
        if (autokey)
            cipher::vigenere::decode<true>(std::span{ target },
                                           std::span{ source },
                                           std::span{ key },
                                           std::span{ alphabet },
                                           ascii_to_index);
        else
            cipher::vigenere::decode<false>(std::span{ target },
                                            std::span{ source },
                                            std::span{ key },
                                            std::span{ alphabet },
                                            ascii_to_index);

    } else {
        if (autokey)
            cipher::vigenere::encode<true>(std::span{ target },
                                           std::span{ source },
                                           std::span{ key },
                                           std::span{ alphabet },
                                           ascii_to_index);
        else
            cipher::vigenere::encode<false>(std::span{ target },
                                            std::span{ source },
                                            std::span{ key },
                                            std::span{ alphabet },
                                            ascii_to_index);
    }

    std::println("{}", target);
}

