from util import padPKCS7
from zlib import compress
from string import ascii_letters, digits
from itertools import product
from base64 import b64encode, b64decode


sessionid = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="

# length of the resultant output
def compression(P):
    request = f'POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid={sessionid}\nContent-Length: {len(P)}\n'.encode() + P
    return len(padPKCS7(compress(request), 16))

if __name__ == "__main__":
    payloadPrefix = "sessionid="
    charset = ascii_letters + digits + '+='
    candidates = ['']
    final_candidate = None

    while not final_candidate:
        min_compressed = None 
        min_candidates = []

        for prefix, char in product(candidates, charset):
            if '=' in prefix and char != '=':
                continue
            session = prefix + char
            payload = (payloadPrefix + session).encode()
            compressSize = [compression(b'\n'.join([payload] * 2 ** i)) for i in range(4)]

            if min_compressed is None:
                min_compressed = compressSize
                min_candidates = [session]

            elif min_compressed >= compressSize:
                if min_compressed == compressSize:
                    min_candidates.append(session)
                else:
                    min_compressed = compressSize
                    min_candidates = [session]

        candidates = []
        for candidate in min_candidates:
            if '=' in candidate:
                if len(min_candidates) < 50:
                    final_candidate = b64encode(b64decode(candidate + '==')).decode()
                    break
            else:
                candidates.append(candidate)
        print(len(candidates))

    print(final_candidate)
    print(final_candidate == sessionid)