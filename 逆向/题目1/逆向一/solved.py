src = "flag{PbkD7j4X|8Wz;~;z_O1}"
flag = "flag{"

for i in xrange(5, 12 + 1):
    flag += chr(ord(src[i]) ^ 7)

for i in xrange(13, 20 + 1):
    flag += chr(ord(src[i]) ^ 8)

flag += "_O1}"
print flag