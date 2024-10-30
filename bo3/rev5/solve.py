
with open("cipher.bin", "rb") as f:
    b = f.read()

b1 = b[0:len(b)//2]
b2 = b[len(b)//2:]
b3 = ([a ^ b for a,b in zip(b1, b2)])

with open("out/cipherxor.bin", "wb+") as f:
    f.write(bytes(b3))
