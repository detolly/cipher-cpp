
with open("hexagon.txt", "r") as f:
    a = f.read()
    b = bytearray([int(b) for b in a.split()])
    print(b.hex())
    with open("hexagon.bin", "wb+") as fb:
        fb.write(b)
