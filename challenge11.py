from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from challenge10 import CBC
from util import padPKCS7


def encryption_oracle(s):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    if randint(0, 1) == 0:
        print('Choose ECB mode')
    else:
        print('Choose CBC mode')
        IV = get_random_bytes(16)
        cipher = CBC(cipher, IV)
    # add dummy bytes before and after the plaintext 
    s = get_random_bytes(randint(5, 10)) + s + get_random_bytes(randint(5, 10))
    s = padPKCS7(s, 16)
    return cipher.encrypt(s)


def detect(encryption_oracle):
    s = bytes([0] * 47)
    t = encryption_oracle(s)
    
    # if there are repeated chunks in the ciphertext, its probably ECB
    if t[16:32] == t[32:48]:
        return 'Detect: ECB'
    return 'Detect: CBC'

if __name__ == '__main__':
    print(detect(encryption_oracle))
