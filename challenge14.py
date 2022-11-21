from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from challenge12 import blockSize, appendedString
from base64 import b64decode
from util import padPKCS7


key = get_random_bytes(16)
randcount = randint(16, 32)
prefix = get_random_bytes(randcount)

# AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
def encryption_oracle(s):
    cipher = AES.new(key, AES.MODE_ECB)
    s = padPKCS7(prefix + s + b64decode(appendedString), 16)
    return cipher.encrypt(s)

# get all blocks of the ciphertext
def getBlocks(s, blocksize):
    return [s[i : i + blocksize] for i in range(0, len(s), blocksize)]


def findPrefixBlock(encryption_oracle, blocksize):
    # To find the index of the block where the prefix ends, we use the oracle to encrypt
    # an empty message and a 1 character message
    x1 = encryption_oracle(b'')
    x2 = encryption_oracle(b'0')
    blocks1 = getBlocks(x1, blocksize)
    blocks2 = getBlocks(x2, blocksize)

    # The first block where the two ciphertexts differ will be the block where the
    # prefix (which was the same for both the inputs) ended.
    for i in range(len(blocks1)):
        if blocks1[i] != blocks2[i]:
            return i


def findPrefixSizeModBlockSize(encryption_oracle, blocksize):
    # Checks if the given ciphertext contains two consecutive equal blocks
    def has_equal_block(blocks):
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                return True
        return False

    # to find the index where the prefix ended, we will encrypt identical bytes,
    # in a number equal to two block_lengths, and we will increase this amount by an incremental
    # offset to see when those bytes will be shifted to be autonomous blocks (encrypted the same way)
    for i in range(blocksize):
        s = bytes([0] * (2 * blocksize + i))
        t = encryption_oracle(s)
        blocks = getBlocks(t, blocksize)
        
        # If the bytes have shifted enough, we can compute the precise index where the prefix ends
        # inside its last block, which is going to be equal to block_length - i
        if has_equal_block(blocks):
            return blocksize - i

    raise Exception('Not using ECB')


def findPrefixSize(encryption_oracle, blocksize):
    return blocksize * findPrefixBlock(encryption_oracle, blocksize) + findPrefixSizeModBlockSize(encryption_oracle, blocksize)

# same as challenge 12
def findNextByte(encryption_oracle, blocksize, prefixsize, knownBytes):
    k1 = blocksize - (prefixsize % blocksize)
    k2 = blocksize - (len(knownBytes) % blocksize) - 1
    k3 = prefixsize - (prefixsize % blocksize)
    s = bytes([0] * (k1 + k2))
    d = {}
    for i in range(256):
        t = encryption_oracle(s + knownBytes + bytes([i]))
        d[t[k3 + k1 : k3 + k1 + k2 + len(knownBytes) + 1]] = i
    t = encryption_oracle(s)
    u = t[k3 + k1 : k3 + k1 + k2 + len(knownBytes) + 1]
    if u in d:
        return d[u]
    return None


if __name__ == "__main__":
    blocksize = blockSize(encryption_oracle)
    prefixsize = findPrefixSize(encryption_oracle, blocksize)
    s = b''
    while True:
        b = findNextByte(encryption_oracle, blocksize, prefixsize, s)
        if b is None:
            break
        s += bytes([b])
    print(s)





