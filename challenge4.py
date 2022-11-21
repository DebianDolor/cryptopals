from binascii import unhexlify
import challenge3

def decrypt(filename):
    f = open(filename, 'r')
    for line in f:
        if line[-1] == '\n':
            line = line[:-1]
        s = unhexlify(line)
        yield s

def detectSingleByteXOR(lines):
    encryptedLines = [challenge3.breakSingleByteXOR(l)[1] for l in lines]
    
    def score(i):
        return challenge3.score(encryptedLines[i])
    
    maxScoreIndex = max(range(len(encryptedLines)), key=score)

    print(maxScoreIndex + 1, encryptedLines[maxScoreIndex].decode())

if __name__ == '__main__':
    detectSingleByteXOR(decrypt('4.txt'))
