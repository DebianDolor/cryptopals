from Crypto.Util.strxor import strxor
from challenge21 import MT19937
from struct import pack

class MT19937Cipher:
    def __init__(self, key):
        self._rng = MT19937(key & 0xffff)
        self._keybytes = b''

    def encrypt(self, plaintext):
        # Work around strxor() not handling zero-length strings
        # gracefully.
        if len(plaintext) == 0:
            return b''

        keystream = self._keybytes
        while len(keystream) < len(plaintext):
            keyblock = pack('<L', self._rng.random())
            keystream += keyblock

        if len(keystream) > len(plaintext):
            self._keybytes = keystream[len(plaintext):]
            keystream = keystream[:len(plaintext)]

        return strxor(plaintext, keystream)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)

