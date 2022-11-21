from aes import cbc_encrypt, cbc_decrypt
from challenge28 import sha1
from Crypto import Random
from Crypto.Cipher import AES
from challenge33 import DiffieHellman
from binascii import unhexlify

def parameter_injection_attack(alice, bob):
    """Simulates a MITM key-fixing attack on Diffie-Hellman with parameter injection."""

    # Step 1: Alice computes A and sends it to Eve (attacker) (thinking it was Bob)
    A = alice.get_public_key()

    # Step 2: Eve changes A with p and sends it to Bob
    A = alice.p

    # Step 3: Bob computes B and sends it to Eve (thinking of Alice)
    B = bob.get_public_key()

    # Step 4: Eve changes B with p and sends it to Alice
    B = bob.p

    # Step 5: Alice finally sends her encrypted message to Bob (without knowledge of MITM)
    _msg = b'Hello, how are you?'
    _a_key = unhexlify(sha1(str(alice.get_shared_secret_key(B)).encode()))[:16]
    _a_iv = Random.new().read(AES.block_size)
    a_message = cbc_encrypt(_a_key, _a_iv, _msg) + _a_iv

    # Step 6: Eve relays that to Bob

    # Step 7: Bob decrypts the message sent by Alice (without knowing of the attack), encrypts it and sends it again
    _b_key = unhexlify(sha1(str(bob.get_shared_secret_key(A)).encode()))[:16]
    _a_iv = a_message[-AES.block_size:]
    _a_message = cbc_decrypt(_b_key, _a_iv, a_message[:-AES.block_size])
    _b_iv = Random.new().read(AES.block_size)
    b_msg_back = cbc_encrypt(_b_key, _b_iv, _a_message) + _b_iv

    # Step 8: Eve relays that to Alice

    # Step 9: Eve decrypts the message (either from a_message or from b_msg_back, it's the same).
    #
    # Instead of (B^a % p) or (A^b % p), the shared secret key of the exercise became (p^a % p)
    # and (p^b % p), both = 0
    mitm_hacked_key = unhexlify(sha1(b'0').encode())[:16]

    # Hack Alice's msg
    mitm_a_iv = a_message[-AES.block_size:]
    mitm_hacked_message_a = cbc_decrypt(mitm_hacked_key, mitm_a_iv, a_message[:-AES.block_size])

    # Hack Bob's msg back 
    mitm_b_iv = b_msg_back[-AES.block_size:]
    mitm_hacked_message_b = cbc_decrypt(mitm_hacked_key, mitm_b_iv, b_msg_back[:-AES.block_size])

    # Check if the attack worked
    print(_msg == mitm_hacked_message_a)
    print(_msg == mitm_hacked_message_b)


if __name__ == '__main__':
    alice = DiffieHellman()
    bob = DiffieHellman()
    parameter_injection_attack(alice, bob)