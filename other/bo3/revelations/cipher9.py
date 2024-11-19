
with open('cipher9.bin', 'rb') as f:
    b = f.read()

res = ""
res2 = ""

n = 0
for i in range(len(b)):
    for k in range(8):
        bit = (1 << (7 - k))
        if (b[i] & bit):
            res2 += "\N{ESC}[31m1"
            res += "1"
        else:
            res2 += "\N{ESC}[32m0"
            res += "0"
        n+=1
        # if n % 2 == 0:
        #     res2+=" "
    if (i+1) % 8 == 0:
        res2+="\n"

print(res.replace("0000000", "/").replace("000", " ").replace("1110", "-").replace("10", "."))#.replace("0", ""))
print(res2)

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
