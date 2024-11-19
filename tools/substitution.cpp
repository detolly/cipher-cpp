
#include <print>
#include <iostream>

#include <argparse.hpp>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/substitution.hpp>

int main(int argc, const char* argv[])
{
    argparse::ArgumentParser parser("substitution");
    
    parser.add_argument("-p", "--plaintext-alphabet")
        .default_value(std::string(cipher::base64::DEFAULT_ALPHABET.begin(), cipher::base64::DEFAULT_ALPHABET.size()));
    parser.add_argument("-c", "--ciphertext-alphabet")
        .required();
    parser.add_argument("-d", "--decode").flag().default_value(false);
    parser.add_argument("--debug").flag().default_value(false);
    parser.add_argument("source").required();

    try {
        parser.parse_args(argc, argv);
    } catch(const std::exception& e) {
        std::println(stderr, "{}", e.what());
        std::exit(1);
    }

    const auto debug = parser.get<bool>("--debug");
    auto source = parser.get<std::string>("source");
    if (debug)
        std::println(stderr, "SOURCE: _{}_", source);

    if (source == "-") {
        source.clear();
        std::cin >> source;
    }

    std::string target;
    target.resize(source.length());

    const auto decode = parser.get<bool>("--decode");
    if (debug)
        std::println(stderr, "DECODE: _{}_", decode);

    const auto plaintext_alphabet = parser.get<std::string>("--plaintext-alphabet");
    if (debug)
        std::println(stderr, "PLAINTEXT_ALPHABET: _{}_", plaintext_alphabet);

    const auto ciphertext_alphabet = parser.get<std::string>("--ciphertext-alphabet");
    if (debug)
        std::println(stderr, "CIPHERTEXT_ALPHABET: _{}_", ciphertext_alphabet);

    const auto source_ascii_to_index = cipher::alphabet::create_ascii_to_index_array(decode ? std::span{ ciphertext_alphabet } : std::span{ plaintext_alphabet });
    const auto target_alphabet = decode ? std::span{ plaintext_alphabet } : std::span{ ciphertext_alphabet };
    if (debug)
        std::println(stderr, "TARGET_ALPHABET: _{}_", std::string_view{ target_alphabet });

    cipher::substitution::substitute(std::span{ target },
                                     std::span{ source },
                                     source_ascii_to_index,
                                     target_alphabet);

    std::println("{}", target);
}

