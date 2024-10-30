
with open("cipher.bin", "rb") as f:
    key = f.read()

l = list(bytes(key))
print(min(l), max(l))
print(l)
print(len(l), sorted(l))

s = sorted(set(l))
print(len(s), s)
