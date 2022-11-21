from Crypto.Cipher import AES
from os import urandom
from util import padPKCS7

BLOCK_SIZE = 16
key = urandom(16)
iv = urandom(16)


prefix = b"comment1=cooking%20MCs;userdata="
suffix = b";comment2=%20like%20a%20pound%20of%20bacon" 

def filter_and_pad(pt):
	pt = pt.replace(b";", b"%").replace(b"=", b"%")
	return prefix + pt + suffix

def encrypt(pt):
	pt = padPKCS7(pt, 16)
	aes = AES.new(key, AES.MODE_CBC, iv)
	ct = aes.encrypt(pt)
	return ct

def cbc_decrypt(ct):
	aes = AES.new(key, AES.MODE_CBC, iv)
	dec = aes.decrypt(ct)
	if b";admin=true;" in dec:
		return True
	return False

def CBC_bitflipping_attack(ct):
	semicolon = ct[len(prefix) - 16] ^ ord("%") ^ ord(";")
	equals = ct[len(prefix) - 10] ^ ord("%") ^ ord("=")
	return ct[:len(prefix) - 16] + bytes([semicolon]) + ct[len(prefix)-15: len(prefix) - 10] + bytes([equals]) + ct[len(prefix) - 9:]

if __name__ == "__main__":
	pt = b";admin=true"
	ct = encrypt(filter_and_pad(pt))
	print (cbc_decrypt(CBC_bitflipping_attack(ct)))