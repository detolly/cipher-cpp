
# with open("cipher.txt", "r") as f:
#     c = f.read().replace('\n', '')
#
# l = [[c[i*4], c[i*4+1], c[i*4+2], c[i*4+3]] for i in range(len(c)//4)]
#
# print(l)

with open("cipher2.bin", "rb") as f:
    c = f.read()

d: dict[int, int] = {}

for b in c:
    if d.__contains__(b):
        d[b] += 1
    else:
        d[b] = 1


for k in d.keys():
    print("{} {}".format(k, d[k]))

#print(d)
