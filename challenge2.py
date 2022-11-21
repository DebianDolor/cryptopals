import binascii
from Crypto.Util.strxor import strxor

if __name__ == "__main__":
    buffer1 = binascii.unhexlify('1c0111001f010100061a024b53535009181c')
    buffer2 = binascii.unhexlify('686974207468652062756c6c277320657965')

    print(strxor(buffer1, buffer2))