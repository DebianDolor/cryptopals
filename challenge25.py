from base64 import b64decode
from util import aes_ecb_decrypt
from challenge18 import aes_ctr
from Crypto import Random
from Crypto.Cipher import AES
from util import xor_data
import struct


class Oracle:

    def __init__(self):
        self._key = Random.new().read(AES.key_size[0])

    # Changes the plaintext of the given ciphertext at offset so that it contains new_text
    def edit(self, ciphertext, offset, new_text):
        # Get the indexes of the first and last block that will be affected by the change
        start_block = int(offset / AES.block_size)
        end_block = int((offset + len(new_text) - 1) / AES.block_size)

        # Find the keystream that would be used to encrypt the bytes in the affected blocks
        keystream = b''
        cipher = AES.new(self._key, AES.MODE_ECB)
        for block in range(start_block, end_block + 1):
            keystream += cipher.encrypt(struct.pack('<QQ', 0, block))

        # Find the precise bytes of the found keystream that would be used to encrypt new_text
        key_offset = offset % AES.block_size
        keystream = keystream[key_offset:key_offset + len(new_text)]

        # Encrypt new_text with the computed same-length keystream
        insert = xor_data(new_text, keystream)

        # Insert the new encrypted chunk in the ciphertext overwriting the underlying bytes at offset
        return ciphertext[:offset] + insert + ciphertext[offset + len(insert):]

    def encrypt(self, plaintext):
        return aes_ctr(plaintext, self._key, 0)


def break_random_access_read_write_aes_ctr(ciphertext, encryption_oracle):
    """
    Since the edit() function will encrypt the new_text with the same keystream used in the original 
    ciphertext (shifted by offset), we can set the offset to 0 and overwrite the plaintext of the 
    ciphertext to be the ciphertext itself. Because in AES CTR, 2 encryption = decryption.
    """
    return encryption_oracle.edit(ciphertext, 0, ciphertext)


if __name__ == "__main__":
    with open("7.txt") as input_file:
        binary_data = b64decode(input_file.read())

    plaintext = aes_ecb_decrypt(binary_data, b'YELLOW SUBMARINE')
    oracle = Oracle()

    # Compute the ciphertext and give it to the attacker
    ciphertext = oracle.encrypt(plaintext)

    print(break_random_access_read_write_aes_ctr(ciphertext, oracle).decode().rstrip())