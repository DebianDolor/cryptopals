from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from util import padPKCS7, unpadPKCS7


key = get_random_bytes(16)


# string to JSON-like format
def profile_for(email):

    def change(s):
        return s.replace(b'&', b'').replace(b'=', b'')

    profile = [
        ['email', email],
        ['uid', '10'],
        ['role', 'user']
        ]

    res = b''    
    for info in profile:
        in4 = [change(x.encode('ascii')) for x in info]
        if res != b'':
            res += b'&'
        res += in4[0] + b'=' + in4[1]
    return res


def encrypt_profile(email):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_profile = padPKCS7(profile_for(email), 16)
    return cipher.encrypt(encrypted_profile)


def decrypt_profile(s):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_profile = unpadPKCS7(cipher.decrypt(s), 16)
    pairs = decrypted_profile.split(b'&')
    profile = []
    for p in pairs:
        profile += [[x.decode('ascii') for x in p.split(b'=')]]
    return profile


if __name__ == "__main__":

    # encrypt the first plaintext:
    # block 1:           block 2 (pkcs7 padded):                             block3:
    # email=foo@bar.co   admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b   &uid=10&role=user

    email1 = 'foo@bar.coadmin' + ('\x0b' * 11)
    encrypt_email1 = encrypt_profile(email1)

    # encrypt the second plaintext:
    # block 1:           block 2:           block 3
    # email=foo@bar.co   com&uid=10&role=   user

    email2 = 'foo@bar.cocom'
    encrypt_email2 = encrypt_profile(email2)

    # the forced ciphertext will cut and paste the previous ciphertexts to be decrypted as:
    # block 1:           block 2:           block 3:
    # email=foo@bar.co   com&uid=10&role=   admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    
    print(decrypt_profile(encrypt_email2[0:32] + encrypt_email1[16:32]))
