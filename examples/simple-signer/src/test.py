from sys import argv
from binascii import hexlify
from os import urandom

arg1 = argv[1]


k = urandom(64)
print(k.hex(), end = '')

