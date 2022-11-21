from util import xor_data, padPKCS7
from aes import cbc_encrypt
from Crypto.Cipher import AES
from binascii import hexlify


def hash_cbc(msg: bytes) -> bytes:
    return AES_encrypt(b"YELLOW SUBMARINE", padPKCS7(msg, 16))[-16:]

def AES_encrypt(key, plaintext, iv = b'\x00' * 16):
    cryptor = AES.new(key, AES.MODE_ECB)
    encrypted = b'' 
    for i in range(0, len(plaintext), 16):
        last_block = cryptor.encrypt(xor_data(plaintext[i : i + 16], iv))
        encrypted += last_block
        iv = last_block
    return encrypted

if __name__ == "__main__":
    msg = b"alert('MZA who was that?');\n"
    forge = b"alert('Ayo, the Wu is back!');//"
    check = b'296b8d7cb78a243dda4d0a61d33bbdd1'

    ''' Blocks of the original msg:
    alert('MZA who w
    as that?');\n\x04\x04\x04
    '''
    print("Real message:")
    print(hexlify(hash_cbc(msg)))
    print(hexlify(hash_cbc(msg)) == check)

    ''' Blocks we need for the forge:
    alert('Ayo, the [space]
    Wu is back!');//
    alert('MZA who w (XOR) hash(above)
    as that?');\n\x04\x04\x04 
    '''
    encryptForge = AES_encrypt(b"YELLOW SUBMARINE", forge)[-16:]

    # instead of the 3rd block's iv is the 2nd one's cipher,
    # we will XOR it with the cipher itself to produce 0 iv
    # (first block of the original msg)
    forge += xor_data(msg[:16], encryptForge) + msg[16:]

    print("Fake one: ")
    print(hexlify(hash_cbc(forge)))
    print(hexlify(hash_cbc(forge)) == check)