from challenge4 import decrypt
from itertools import combinations
from binascii import hexlify

def score(x):
    '''
    break the ciphertext into blocks of 16
    '''
    blocks = [x[i : i + 16] for i in range(0, len(x), 16)]
    pairs = combinations(blocks, 2)
    isTheSame = 0
    for p in pairs:
        if p[0] == p[1]:
            isTheSame += 1
    return isTheSame


if __name__ == "__main__":
    lines = decrypt('8.txt')
    lineNumber = 1
    for l in lines:
        if score(l) > 0:
            print(f'Found at line: {lineNumber}')
            print(hexlify(l))
        lineNumber += 1