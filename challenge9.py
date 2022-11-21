from util import padPKCS7

if __name__ == "__main__":
    key = b'YELLOW SUBMARINE'
    result = padPKCS7(key, 20)
    print(result)
    print(result == b'YELLOW SUBMARINE\x04\x04\x04\x04')