from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode
from util import padPKCS7

appendedString = b'''
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
'''

key = get_random_bytes(16)

# AES-128-ECB(your-string || unknown-string, random-key)
def encryption_oracle(s):
    s = padPKCS7(s + b64decode(appendedString), 16)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(s)

# Find the block size of the cipher
def blockSize(encryption_oracle):
    l = len(encryption_oracle(b''))
    i = 1
    while True:
        s = bytes([0] * i)
        t = encryption_oracle(s)

        if len(t) != l:
            return len(t) - l
        i += 1

def detectECB(encryption_oracle, blocksize):
    s = get_random_bytes(blocksize) * 2
    t = encryption_oracle(s)
    if t[0:blocksize] != t[blocksize:2*blocksize]:
        raise Exception('Not using ECB')

# find the next byte of the appended string
def findNextByte(encryption_oracle, blocksize, knownBytes):
    # craft an input block that is 1 byte short
    s = bytes([0] * (blocksize - (len(knownBytes) % blocksize) - 1))
    d = {}
    
    # make a dictionary of every possible last byte
    for i in range(256):
        t = encryption_oracle(s + knownBytes + bytes([i]))
        d[t[0 : len(s) + len(knownBytes) + 1]] = i
    t = encryption_oracle(s)
    u = t[0 : len(s) + len(knownBytes) + 1]
    # match the output of the one-byte-short input to one of the entries in the dictionary
    if u in d:
        return d[u]
    return None


if __name__ == '__main__':
    blocksize = blockSize(encryption_oracle)
    detectECB(encryption_oracle, blocksize)
    s = b''
    while True:
        b = findNextByte(encryption_oracle, blocksize, s)
        if b is None:
            break
        s += bytes([b])
    print(s)
