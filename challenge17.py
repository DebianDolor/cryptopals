from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from aes import cbc_encrypt, cbc_decrypt, BadPaddingException, get_blocks, xor_bytes, unpad


KEY = get_random_bytes(16)

strings = [
"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]


def encrypt_oracle(s):
    iv = get_random_bytes(16)
    s = b64decode(s)
    return iv, cbc_encrypt(KEY, iv, s)


def checkPadding(iv, ciphertext):
    try:
        cbc_decrypt(KEY, iv, ciphertext)
        return True
    except BadPaddingException:
        return False


def decrypt_block(oracle, prev_block, current_block):
    current_block_pre_xor = []

    for i in range(len(current_block)):
        valid_bytes = bruteforce_pre_xor_byte(oracle, current_block_pre_xor,
                                              current_block)

        assert((i == 0 and len(valid_bytes) in [1, 2]) or
               (i > 0 and len(valid_bytes) == 1))
        valid_byte = (valid_bytes[0] if i > 0 else
                      determine_last_pre_xor_byte(oracle, valid_bytes,
                                                  current_block))

        assert(valid_byte is not None)
        padding_byte = len(current_block_pre_xor) + 1
        current_block_pre_xor.insert(0, valid_byte ^ padding_byte)

    return xor_bytes(current_block_pre_xor, prev_block)


def bruteforce_pre_xor_byte(oracle, prev_block, current_block):
    valid_bytes = []
    padding_byte = len(prev_block) + 1
    for byte in range(256):
        expected_padding = bytes([padding_byte] * padding_byte)
        padding_ending = xor_bytes(expected_padding[:-1], prev_block)

        padding = bytes([byte]) + padding_ending
        assert(len(padding) == len(expected_padding))

        prefix = bytes([0] * (16 - len(padding)))

        # if padding is valid
        if oracle(prefix + padding, current_block):
            valid_bytes.append(byte)

    return valid_bytes


def determine_last_pre_xor_byte(oracle, valid_bytes, current_block):
    verified_byte = None
    for byte in valid_bytes:
        original_prev_block = bytes([0] * 14 + [0, byte])
        tampered_prev_block = bytes([0] * 14 + [1, byte])

        if (oracle(original_prev_block, current_block) and
                oracle(tampered_prev_block, current_block)):
            assert(verified_byte is None)
            verified_byte = byte

    return verified_byte


if __name__ == "__main__":
    for s in strings:
        iv, encrypted = encrypt_oracle(s)

        blocks = [bytes(iv)] + get_blocks(encrypted)
        decrypted_blocks = [decrypt_block(checkPadding, blocks[i-1], blocks[i])
                            for i in range(1, len(blocks))]

        padded_plaintext = b"".join(decrypted_blocks)
        plaintext = unpad(padded_plaintext)

        print(plaintext.decode('ascii'))
        assert(b64encode(plaintext).decode('ascii') == s)
