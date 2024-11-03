#!/bin/bash
clang++ -O3 test.cpp -march=native -std=c++26 -I. -Wall -Werror -Wconversion -fconstexpr-steps=1000000000 -fsyntax-only && echo "Pass!"
