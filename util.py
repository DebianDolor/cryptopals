from Crypto.Cipher import AES
import base64
import challenge15
import hashlib
import socket
import socketserver

class Conn:
    def __init__(self, o):
        if isinstance(o, socket.socket):
            f = o.makefile(mode='rwb', buffering=0)
            self._rfile = f
            self._wfile = f
        elif isinstance(o, socketserver.StreamRequestHandler):
            self._rfile = o.rfile
            self._wfile = o.wfile
        else:
            raise Exception('unexpected')

    def readline(self):
        return self._rfile.readline().strip()

    def readnum(self):
        return int(self.readline())

    def readbytes(self):
        return base64.b64decode(self.readline())

    def writeline(self, line):
        self._wfile.write(line + b'\n')

    def writenum(self, num):
        self.writeline(str(num).encode('ascii'))

    def writebytes(self, bytes):
        self.writeline(base64.b64encode(bytes))

def derivekey(s):
    sha1 = hashlib.sha1()
    sha1.update(str(s).encode('ascii'))
    return sha1.digest()[:16]

def encrypt(key, iv, message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(padPKCS7(message.encode('ascii'), 16))

def decrypt(key, iv, encryptedMessage):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return challenge15.unpadPKCS7(cipher.decrypt(encryptedMessage)).decode('ascii')

def aes_ecb_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(data))

def is_pkcs7_padded(binary_data):
    padding = binary_data[-binary_data[-1]:]
    return all(padding[b] == len(padding) for b in range(0, len(padding)))

def pkcs7_unpad(data):
    if len(data) == 0:
        raise Exception("input is empty")

    if not is_pkcs7_padded(data):
        return data

    padding_len = data[len(data) - 1]
    return data[:-padding_len]

def padPKCS7(x, k):
    ch = k - (len(x) % k)
    return x + bytes([ch] * ch)

def unpadPKCS7(x, k):
    i = x[-1]
    return x[0:-i]

def rrot32(x, n):
    x = x & 0xffffffff
    return (x >> n) | ((x << (32 - n)) & 0xffffffff)

def lrot32(x, n):
    return rrot32(x, 32 - n)

def xor_data(b1, b2):
    return bytes([b1 ^ b2 for b1, b2 in zip(b1, b2)])