from challenge39 import RSA, mod_inv, int_to_bytes
from random import randint


# unpadded message recovery attack on the rsa_server which does not use padding
def unpadded_message_recovery(ciphertext, rsa_server):
    e, n = rsa_server.get_public_key()

    # Let S be a random number > 1 mod N
    while True:
        s = randint(2, n - 1)
        if s % n > 1:
            break

    # Create a new forged ciphertext
    # C' = ((S**E mod N) C) mod N
    new_ciphertext = (pow(s, e, n) * ciphertext) % n

    # Decipher it and convert the deciphered string to an int
    new_plaintext = rsa_server.decrypt(new_ciphertext)
    int_plaintext = int.from_bytes(new_plaintext, byteorder='big')

    # Recover the original plaintext as int, remembering to be careful about division in cyclic groups
    '''
          P'
    P = -----  mod N
          S
    '''
    r = (int_plaintext * mod_inv(s, n)) % n

    # Convert it back to bytes and return it
    return int_to_bytes(r)


class RSAServer:
    """
    This server allows to submit an arbitrary RSA blob and will return the corresponding plaintext
    decrypted with the private key stored on the server. However, it keeps hashes of the messages that
    have been decrypted and rejects the decryption when a ciphertext is submitted more than once.
    """

    def __init__(self, rsa):
        self._rsa = rsa
        self._decrypted = set()

    def get_public_key(self):
        return self._rsa.e, self._rsa.n

    def decrypt(self, data):
        if data in self._decrypted:
            raise Exception("this ciphertext is decrypted")
        self._decrypted.add(data)
        return self._rsa.decrypt(data)


if __name__ == '__main__':
    plaintext = b"this is a test"
    rsa = RSA(1024)
    ciphertext = rsa.encrypt(plaintext)
    print(ciphertext)
    rsa_server = RSAServer(rsa)

    recovered = unpadded_message_recovery(ciphertext, rsa_server)
    print(recovered)
    print(recovered == plaintext)