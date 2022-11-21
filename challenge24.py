from util import xor_data
from Crypto import Random
from Crypto.Random.random import randint
from challenge21 import MT19937
from binascii import hexlify
import struct


class MT19937Cipher:

    def __init__(self, key):
        self._rng = MT19937(key)

    def encrypt(self, plaintext):
        keystream = b''
        # padding thing
        while len(keystream) < len(plaintext):
            keystream += struct.pack('>L', self._rng.extract_number())

        return xor_data(plaintext, keystream)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)


def bruteforce_mt19937_seed(ciphertext, known_plaintext):
    """
    bruteforce all 16-bit seeds (key for the MT19937 stream cipher) until the
    ciphertext decrypts to a message containing our username (known part of the plaintext).
    """
    print("> Brute-forcing all possible seeds...")

    for guessed_seed in range(2**16):
        candidate = MT19937Cipher(guessed_seed).decrypt(ciphertext)

        if known_plaintext in candidate:
            print("> Seed found:", guessed_seed)
            return guessed_seed

    raise Exception("Seed not found")


if __name__ == '__main__':
    # generate a random seed
    seed = randint(0, 2 ** 16 - 1)

    # generate the plaintext which will be encrypted to get the password token
    random_prefix = Random.new().read(randint(0, 100)) + b';'  
    known_plaintext = b'test'                        # known part 
    random_suffix = b';' + Random.new().read(12)

    ciphertext = MT19937Cipher(seed).encrypt(random_prefix + known_plaintext + random_suffix)
    guessed_seed = bruteforce_mt19937_seed(ciphertext, known_plaintext)

    print("> Decrypted password reset plaintext:", hexlify(MT19937Cipher(seed).encrypt(ciphertext)))