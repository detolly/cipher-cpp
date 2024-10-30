import os

with open("cipher.txt", "r") as f:
    s = sorted(set(f.read().replace('\n', "")))

print(s)
print(len(s))

