from challenge43 import DSA, mod_inv
from Crypto.Random.random import randint

def dsa_parameter_tempering():
    """Makes sure that with a proper DSA parameter tampering we can generate valid signatures for any message."""

    # g = p + 1
    dsa = DSA(g=DSA.DEFAULT_P + 1)

    # Test that a legit signature works properly
    some_text = b"Let's see what happens when I sign this message with (g = p + 1) DSA"
    legit_signature = dsa.sign(some_text)
    print('Check legitimate signature:')
    print(dsa.verify(some_text, legit_signature[0], legit_signature[1]))

    # Create a forged signature
    #
    # for any arbitrary z:
    '''
     r = ((y**z) % p) % q

           r
     s =  --- % q
           z
    '''
    z = randint(1, 10)
    forged_r = pow(dsa.y, z, DSA.DEFAULT_P) % DSA.DEFAULT_Q
    forged_s = (forged_r * mod_inv(z, dsa.DEFAULT_Q)) % dsa.DEFAULT_Q

    # Test any random strings
    print("Verify any message:")
    print(f"Hello, world: {dsa.verify(b'Hello, world', forged_r, forged_s)}")
    print(f"Goodbye, world: {dsa.verify(b'Goodbye, world', forged_r, forged_s)}")
    print(f"This is a test: {dsa.verify(b'This is a test', forged_r, forged_s)}")


if __name__ == '__main__':
    dsa_parameter_tempering()
