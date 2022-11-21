import binascii
from base64 import b64encode

def hexToBase64(s):
    decoded = binascii.unhexlify(s)
    return b64encode(decoded).decode('ascii')

def main():
    data = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b64 = hexToBase64(data)
    print(b64)
    print(b64 == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

if __name__ == "__main__":
    main()
