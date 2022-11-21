from struct import pack
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from util import padPKCS7
from util import xor_data
import struct

class CTR:
    def __init__(self, ECB, nonce):
        self._ECB = ECB
        self._nonce = nonce
        self._blocksize = 16
        self._keybytes = b''
        self._blockcount = 0

    def encrypt(self, plaintext):
        if len(plaintext) == 0:
            return b''

        keystream = self._keybytes
        while len(keystream) < len(plaintext):
            keyblock = self._ECB.encrypt(pack('<QQ', self._nonce, self._blockcount))
            keystream += keyblock
            self._blockcount += 1

        if len(keystream) > len(plaintext):
            self._keybytes = keystream[len(plaintext):]
            keystream = keystream[:len(plaintext)]

        return strxor(plaintext, keystream)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)

def aes_ctr(data, key, nonce):
    output = b''
    counter = 0

    while data:
        concatenated_nonce_and_counter = struct.pack('<QQ', nonce, counter)
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_counter = cipher.encrypt(padPKCS7(concatenated_nonce_and_counter, 16))
        output += xor_data(encrypted_counter, data[:AES.block_size])
        data = data[AES.block_size:]
        counter += 1

    return output


if __name__ == '__main__':
    
    base64Decrypted = b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    key = b'YELLOW SUBMARINE'
    cryptor = CTR(AES.new(key, AES.MODE_ECB), 0)
    print(cryptor.decrypt(base64Decrypted))
    
