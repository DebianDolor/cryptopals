from hmac import digest
from random import randrange, seed
from challenge39 import mod_inv

def get_mac(key, msg):
    return digest(key.to_bytes(encryption_len, 'big'), msg, 'md5')

if __name__ == "__main__":
    p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
    # g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
    q = 236234353446506858198510045061214171961

    # smaller divisors of j (< 2^16)
    factors = [2, 5, 109, 7963, 8539, 20641, 38833, 39341, 46337, 51977, 54319, 57529]
    prod = 1

    # only keep factors that sum up to be greater than q
    for i, v in enumerate(factors):
        prod *= v
        if prod > q: break
    del factors[i + 1:]


    encryption_len = (p.bit_length() + 7) // 8
    msg = b"crazy flamboyant for the rap enjoyment"
    # bob's secret key
    secret = randrange(1, q)

    # remainder [factors]
    remainders = []

    for factor in factors:
        # get element of order `factor`
        '''
         h := rand(1, p)^((p-1)/factor) mod p
        '''
        exponent = (p - 1) // factor
        while True:
            h = randrange(1, p)
            h = pow(h, exponent, p)
            if h != 1: break

        # get message encrypted with bob's invalid public key
        '''
        msg := "crazy flamboyant for the rap enjoyment"
        mac := get_mac(K, msg)
        K   := h^secret mod p -- output shared secret
        '''
        mac = get_mac(pow(h, secret, p), msg)

        # bruteforce remainders
        for i in range(factor):
            if mac == get_mac(pow(h, i, p), msg):
                remainders.append(i)
                break

    # chinese remainder theorem
    recovered = 0
    for factor, remainder in zip(factors, remainders):
        factor_ = prod // factor
        inverse = mod_inv(factor_, factor)
        recovered = (recovered + remainder * inverse * factor_) % prod

    print(recovered)
    print(recovered == secret)