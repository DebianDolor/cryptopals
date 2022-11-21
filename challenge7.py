import base64
from Crypto.Cipher import AES

if __name__ == "__main__":
    plaintext = base64.b64decode(open('7.txt', 'r').read())
    key = b'YELLOW SUBMARINE'
    ciphertext = AES.new(key, AES.MODE_ECB)
    print(ciphertext.decrypt(plaintext).decode())