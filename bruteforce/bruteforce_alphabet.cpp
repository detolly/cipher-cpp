#include <cstdio>
#include <print>
#include <vector>

#include <cipher/alphabet.hpp>
#include <cipher/base64.hpp>
#include <cipher/cipher.hpp>
#include <cipher/vigenere.hpp>
#include <cipher/bruteforce.hpp>

using namespace cipher::bruteforce;

template<auto plaintext_alphabet, auto ciphertext, auto key, auto heuristic, auto you_win, auto progress_report>
constexpr static void bruteforce_alphabet_vigenere(base64_alphabet_bruteforce_state& state)
{
    constexpr static auto get_next_char = []<auto next>(base64_alphabet_bruteforce_state& state) {
        const auto source_char = ciphertext[state.ciphertext_index];
        const auto key_char = key[(state.ciphertext_index) % key.size()];
        state.alloc_at_all_index(key_char, [&](const char key_char) {
            state.alloc_at_all_index(source_char, [&](const char source_char) {
                const auto index = cipher::vigenere::alphabet_index<false>(
                    state.ascii_to_index,
                    64,
                    source_char,
                    key_char);
                state.template alloc_all_char_at_index<plaintext_alphabet>(
                    index, 
                    [&](const char c){
                        next(state, c);
                    });
            });
        });
    };

    bruteforce_base64<base64_alphabet_bruteforce_state, ciphertext, get_next_char, heuristic, you_win, progress_report>(state);
}

template<auto ciphertext>
constexpr static auto translate_plaintext_substitution(base64_alphabet_bruteforce_state& alphabet, const std::size_t ciphertext_index, const char char_to_translate)
{
    const auto source_char = ciphertext[ciphertext_index];
    const auto index = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(source_char);
    alphabet.try_alloc(index, char_to_translate);
}

template<auto ciphertext, auto heuristic, auto you_win, auto progress_report>
constexpr static void bruteforce_alphabet_substitution(base64_alphabet_bruteforce_state& state)
{
    constexpr static auto get_next_char = []<auto next>(base64_alphabet_bruteforce_state& state) {
        const auto cipher_char = ciphertext[state.ciphertext_index];
        const auto cipher_index = cipher::index_in_alphabet<cipher::base64::DEFAULT_ALPHABET>(cipher_char);
        state.template alloc_all_char_at_index<cipher::base64::DEFAULT_ALPHABET>(
            cipher_index ,
            [&](const char c){
                next(state, c);
            });
    };

    bruteforce_base64<base64_alphabet_bruteforce_state, ciphertext, get_next_char, heuristic, you_win, progress_report>(state);
}

constexpr static const auto ciphertext = cipher::buffer(
    "kCmlgFi6GuJNgkNI1Q41fbfyLoCFTCvlqkZiI0KIAXAzP1U1uy1BE4U"
    "fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xIe8FOhAGJZ7g4in0wn"
    "dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1"
    "JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1");
// constexpr static const auto ciphertext = cipher::buffer(
//     "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3");
// constexpr static const auto ciphertext = cipher::buffer(
//     "iW9cXmzOU7ZuZBtW40b3ngK2icE75R0Vb7HvniQd7aCAh5aQRum8gp91EzIDtgySXvGUQxAn3gOM2gr"
//     "BpiLf3QjdfBwjLForeHhqEX59HyOVq9vos22eBNP3ouDrTTNZpwHZPeJDGVt1oauYa+pgDuG7FzHdHFq"
//     "Tfsu5YIdFN1h07TH3ytjgZKBtCRTtSHfoKU63MvLd1J+UYTzGic90jSJY7k6gWRDDnRfQuthzgo49ELKNR"
//     "ei5W58fAf27hnhUVMEi5KVIXqrI4J7ttys971vENRROhGz8JkhnqJbtKuftKUXgpt2/Iy/fGI6iHT/aaQg7Yddd2"
//     "YocXsDE7D8NqXr3JqS0m5tSMdFYsipJONks1Iu21O1fwJhbXVQfbpkFnwXY1kLJJL8Yq+3wjeCYYmySm"
//     "WU6rGMH0Jz/g0B2T3CG+uKU2i3UZ0Yx0tl4ugiDkrZnGuZKmdSkJJPvdDqJeEjpFKY+81e7bVzTx7qHKv"
//     "pITj3E/HH/Ac8Jd9zOOqIb+stbpJDRYI6hMP8uqKyPydHe40v0sXjCkwTj/letJVtNseMqQ6NGEAIdazM54rJ"
//     "UeMPq3wglsndvYMoKILOXocFaydVYzAH4iwnoxxk2kZ3zoV4YJCxIKwPhYPWd/2ELxFAv6JrBzkNLTsEg"
//     "fWBvRLtpLcokOfyuMyOgwZizP9zQx+wG2+GQ2k/Lh8fX2wAgPl8k8/2qzw00vpYb+Olh6LwQKKeWed80a"
//     "A2eUle1qPtW2XKDOEXRvZ8T8EkSYCqIiLtfQgpJmmVBji6a0EGa6TRY/24qzHpW1KjigEblNI4nCAxI+iSy"
//     "ex0DxUv8TzbJaxrH/WsyQKcTEfv7IdisbjY59iD1g7KAuzjuQBzc4aWeLCfnPgbZYcXr8+BSMuz7hK9+xkM"
//     "0rLx+gB011wNQog9/bmpWZkqokffqVwV0G1xKveSIez1fhZ29scH53pftJ4OGPX5CToN3ZbxObZ7wdIF2j"
//     "XlNHOOjHtEvrENghf9+tFbO1+kToYzrz+m8uuHgmn/1/43570i9CKBk+DqfOSFXDs3kSNqkr5+5Gu9xhKE"
//     "4YlZSm/F+yL9/Z/mqqx9RTfuRujzgjBWnTqDu2VpBT9jL6UMLGMQKP6bVQJuL2EwNtcoTMV2bC2RT6b"
//     "UGtDQ+LZIur1QnbfhDjqVUS8zLT5meT5yUQm3mfkj63wVDZUndNbj8Kujpq6CvXK8tq/TurA6uM85ABY1"
//     "QzzhvdvekL1P0Jeotbbw3ep7eDhq/QgYDBkenb7wdZQAoAcG7XxixAL4XWubsBT6bgGROcszdi16qFLb4"
//     "WQ55EU96n9xhN4wMMNPx1GVy6SLU9aluQ4EiY9hYphc1PAvONI9adiX+VqubTiRuStdS9/LZjf9F5wI8f8"
//     "eVLPDUylOp0rFQ/J3UJh6ymfHCsZum5nRPRPPlOYAyXJ/Yyl1YqqUF9YnMFgbRiBkNKlSys5w45TWvLw"
//     "XnP8ARRfF6VuCQfcnkVLfuGlwZqrBUsJ+bIAMqqN91A8PTnoEd541KAHDVfynwDJ5YVgkEyT467DJVK4"
//     "SHxrLy1Imcks3X2enR3rtq8Ychj/m/fuL5w4fUULFvnAvEyZBM1VjnbgQEjZ60LUp6iOoU0FuIK2ZNsYqkCq"
//     "f1vZjIkoVx3AxrkbknZyjsHW8TzyL6AAK6bsSMMLADQpW/HGCOSrR3H9CzIQHJw9fnBBYqd3MIQFQ5G"
//     "NUY9+Ebq0UAvXUviVyHVIeU0EuQkdxjaKhrtAmZ5UotEdvmi0yi89AjPOQ8LRlTS4J8kJvRSmCzkvZ5m31"
//     "3kmIM9BWlbkXEdZ2SJ56AaqQ0dZutsGgBgirHVW7jHbpapXv/OGrDbbN5SgZqf0hN2Icgl7Qyoe87PdgMJ"
//     "27+TngkPw2+YrpGgSplrr82QuubHGeXPxZuDBRNdhK4ke5Z8eJ6pmwbPgpr26+s5vfMxcE959wX0POQ"
//     "oQLf50bCXcwltIR/j70FENcaQLnUIgDO8ExtARtpnj9h38HzGYReNXaRkFQuY4XeDnTEPfh40I4/vYdKY4i"
//     "yxR/8vLAqpxM6326n4MHAC7Szx0Ar7P3cqTek8z6dOiG69MpcSa5WWd0GXeqrXx1FNs06TvSHHt7ACf"
//     "UEeqKjFO5yLbcgNeayWPXh0rmJahEJtfZEmgki7YNpud6vbT5au1h1MxsaoxbizE7heQF7MH1kswbSZKj"
//     "La/s8qMsB");
// constexpr static const auto ciphertext = cipher::buffer(
//     "nee1bHowKtghExi46wfcRfcWMAFtUVkDuKBtj75XtJy0uaD4cYWtsXKmIpw7YBWFqjpHmb8kAC2UXj71o"
//     "JQANSczif2D3d2RZY8JRmD6uYhJ1ZfrLHUXdx9t9iXnTUmr6xcGCNygexlYKccTe/2D3UW84Z1ONzz/g7"
//     "1oRFrFm7KV5ML4Rbs0+2F7zvp4n3n3yEJJZOF5vCial+sjxnp4gJev9G2Vrc5dD4XP6fASrXcPFMoheWd/"
//     "3lPVty/iAlK53PftLauCD6XXpJKhGFLNYCz1sYJbYcZqe+O/Y7xRlxtfkH7t399BDRuD6FNYN41PCgqTic5C"
//     "3L3KZjM5PR+yYbTwc/I9EVbe5MshfJahG866wz6u+H/KeoxcPaYnBdGMVLLwA1iTEzQughiqcsqersrAZ3"
//     "Q/Ghr85nuKf49w2dnsw3LDQwExFXWSMZ5j5GwV29zXCC4AYyEtsJ4RzWBFxboYd3tYxsQdKkIaW+CS"
//     "0rWuCGCHgzDPcpeYgSoVJ5zk5a+lrVbjlfeOO+9oK0vY5qpdn+ek6Lmv4GRioZXze7kld3FQZ1EjDzkvb6T"
//     "7SwGZqQClbE6yzfwDEwXDL2HV0dEdCkUsh8kQWiUrIPHlLFebXdkWIGkgAgTLMcdi7zRWnPjMzuJ29Bl"
//     "ULggwyPIET5xxXnhVLAzHGTnZtmfdmadMMRMW4FiPLykaIDmiBAo12OJWhX7ie7Q4iDwvaMI9146Ywx"
//     "eGeri5+6Zg1xJAcmpT11MjJjLcmdwVlmzzDDBXDfgBgyQbYBOqK9VYAtX6WT0gXvlg/aFBQHawljBIfhJT"
//     "weSlwijr4NRW1YD6eYFt3lP9kV2a4j3EoxkTFzL9xPBCbO5EOFDcBiHZGWUCFU/eHbdkfg1dW8xV7iLgd"
//     "eSnGmxUnkW+9s8yxUFLy0s8ZOgGHJ7LB6TfEz6FZpBfgjOcE86h1GF98HnoPwLnyiXI2hkAL+2tksHJjdn"
//     "fGrb54pNF4pEVkbm2zSSfW5ASuLWeXBEA7ypfIrio4gQPBtqj19uebWRsyyzTs3QZnYsLQAV+MnjJVk3jF"
//     "F1WRcGS3iSCJz4k3YZjUGE=");
// [[maybe_unused]] constexpr const auto key = cipher::buffer("TheGiant");

thread_local std::uint64_t iteration{0};
std::vector<base64_alphabet_bruteforce_state> alphabets;
static void bruteforce_alphabet(const std::string_view plaintext)
{
    constexpr static auto you_win = [](const auto& state) {
        alphabets.push_back(state);
        std::println("FOUND ALPHABET: {:64} PLAINTEXT: {}", state.alphabet_string_view(), state.plaintext_string_view());
    };
    constexpr static auto progress_report = [](const auto& state){
        if (iteration++ % 100000000 == 0) 
            std::println(stderr, "ALPHABET: {} PLAIN: \n{:64} ", state.alphabet_string_view(), state.plaintext_string_view());
    };

    // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyz");
    // constexpr static auto common_alphabet = cipher::alphabet::create("ABCDEFGHIJKLMNOPQRTSUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!.,:@()\"'/\n\r ");
    // constexpr static auto common_alphabet = cipher::alphabet::create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
    // constexpr static auto common_alphabet = cipher::alphabet::create("0123456789 ");
    constexpr static auto heuristic = [](const auto plain) {
        // return cipher::is_in_alphabet<common_alphabet>(plain);
        return cipher::is_print(plain);
        // return cipher::is_common_print(plain);
    };

    // auto alphabet = Base64Alphabet::create_starting_configuration("");
    // auto alphabet = Base64Alphabet::create_alphabet_with_plaintext<translate_plaintext_vigenere<plaintext_alphabet, ciphertext>>("Der Riese");
    auto state = cipher::bruteforce::create_state_with_plaintext<base64_alphabet_bruteforce_state, translate_plaintext_substitution<ciphertext>>(plaintext);

    // bruteforce_alphabet_vigenere<plaintext_alphabet, ciphertext, key, heuristic, you_win, progress_report>(alphabet, plaintext);
    bruteforce_alphabet_substitution<ciphertext, heuristic, you_win, progress_report>(state);

    for(const auto& alphabet : alphabets) {
        std::println(stderr, "FOUND PLAIN: {:64} ALPHABET: {}", alphabet.plaintext_string_view(), alphabet.alphabet_string_view());
    }

    std::println("done?");
}

int main(int, const char* argv[])
{
    bruteforce_alphabet(std::string_view{ argv[1] });
    return 0;
}

