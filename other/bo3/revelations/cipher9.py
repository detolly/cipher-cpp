
with open('cipher9.bin', 'rb') as f:
    b = f.read()

res = ""

for i in range(len(b)):
    for k in range(8):
        bit = (1 << (7 - k))
        if (b[i] & bit):
            res += "\N{ESC}[31m1"
            # res += "-"
        else:
            res += "\N{ESC}[32m0"
            # res += "."
    if (i+1) % 8 == 0:
        res += "\n"

print(res)

# # print(res)
# n = 8
# while n <= 32:
#     print("")
#     print("new {}".format(n))
#     print("")
#     for i in range(len(res)):
#         if i % (n * 6) == 0: 
#             print("")
#         print(res[i], end="")
#     k = 0
#     n += 1
