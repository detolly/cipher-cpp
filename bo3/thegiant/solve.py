
with open("cipher.bin", "rb") as f:
    b = f.read()

print(bytes(b).hex())

w = list(b)
# print(len(w))
# print(w)

window1 = [1,0,0,0,1,1,1,0,1,1,
           1,1,0,0,1,0,1,0,0,1,
           1,0,0,1,1,1,1,1,0,1,
           1,0,0,0,1,1,0,0,1,1,
           1,1,1,0,0,1,1,1,1,1]

window2 = [1,1,1,1,1,0,0,1,1,1,
           1,1,0,0,1,1,0,0,0,1,
           1,0,1,1,1,1,1,0,0,1,
           1,0,0,1,0,1,0,0,1,1,
           1,1,0,1,1,1,0,0,0,1]

window3 = [1,1,1,1,1,1,0,0,0,1,
           1,0,0,0,1,1,0,0,1,1,
           0,0,0,1,1,1,1,1,1,1,
           1,0,0,0,0,0,0,0,0,1,
           1,1,0,0,0,0,0,0,1,1]

window4 = [1,0,0,0,0,0,0,1,1,1,
           1,1,0,0,1,1,0,0,0,1,
           1,1,1,1,1,1,1,1,1,1,
           1,0,1,1,0,1,0,0,0,1,
           1,1,0,1,1,1,0,0,1,1]

window5 = [1,1,1,1,1,1,1,1,1,1,
           1,1,0,0,1,1,1,0,1,1,
           1,1,1,1,1,1,1,1,1,1,
           1,0,1,1,1,1,0,0,1,1,
           1,1,1,1,1,1,1,1,1,1]

def make_bytes_from_window(window) -> bytearray:
    arr = []
    currentbyte = 0
    for i in range(len(window)):
        if i % 8 == 0 and i != 0:
            arr.append(currentbyte)
            currentbyte = 0
        currentbyte = (currentbyte << 1) | window[i]
    if currentbyte != 0:
        lastbyte = 0
        for i in range(len(window) % 8): lastbyte |= (1 << 7 - i) 
        arr.append(lastbyte)
    return bytearray(arr)

allwindows = window1 + window2 + window3 + window4 + window5
print(len(allwindows))
arr = make_bytes_from_window(allwindows)

print(list(arr))
print(arr.hex())

for i in range(len(arr)):
    arr[i] = 0b11111111 - arr[i]
print(list(arr))
print(arr.hex())
print(len(list(arr)))

for i in range(12):
    for j in range(12):
        print("{:2x} ".format(w[i*12+j]), end="")
    print()

