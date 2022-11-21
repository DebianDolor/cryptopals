from base64 import b64decode
from challenge3 import breakSingleByteXOR
from challenge5 import repeatingKeyXor
from itertools import combinations, zip_longest


def Hamming(x, y):
    return sum([bin(x[i] ^ y[i]).count('1') for i in range(len(x))])


'''
break the ciphertext into blocks of KEYSIZE length,
and transpose the blocks
'''
def breakRepeatingKeyXor(x, k):
    blocks = [x[i : i + k] for i in range(0, len(x), k)]
    transposedBlocks = list(zip_longest(*blocks, fillvalue=0))
    key = [breakSingleByteXOR(bytes(x))[0] for x in transposedBlocks]
    return bytes(key)


"""
For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, 
and find the edit distance between them. 
Normalize this result by dividing by KEYSIZE. 
"""
def normalizedEditDistance(x, keySize):
    blocks = [x[i : i + keySize] for i in range(0, len(x), keySize)][0:4]
    pairs = list(combinations(blocks, 2))
    scores = [Hamming(p[0], p[1])/float(keySize) for p in pairs][0:6]
    return sum(scores) / len(scores)


if __name__ == "__main__":
    plaintext = b64decode(open('6.txt', 'r').read())
    '''
    The KEYSIZE with the smallest normalized edit distance is probably the right key
    '''
    k = min(range(2, 41), key=lambda keySize: normalizedEditDistance(plaintext, keySize))

    key = breakRepeatingKeyXor(plaintext, k)
    y = repeatingKeyXor(plaintext, key)
    print(f'Key:\n{key.decode()}')
    print(f'Ciphertext:\n{y.decode()}')
