from hmac import digest
from random import randrange
from challenge39 import mod_inv


p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
q = 335062023296420808191071248367701059461
g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357

def pollard(y, lowerbound_exp, upperbound_exp, k=16, p=p, q=q, g=g):
    
    # f(y) = 2^(y mod k)
    f = lambda y: 2 ** (y % k)

    '''
    avg of f is (2 ^ k - 1) / k
    multiplied by 4 to make better chance of finding collision -> (2 ^ (k+2) - 4) / k 
    '''
    N = (2 ** (k + 2)) // k

    ''' control sequence
    get the endpoint
    '''
    xT = 0
    yT = pow(g, upperbound_exp, p)

    ''' accumulate the total distance traveled in xT 
    y := y * g^f(y) [mod p]
    '''
    for _ in range(N):
        fT = f(yT)
        xT += fT
        yT = (yT * pow(g, fT, p)) % p

    ''' then search if we met
    do a similar loop, starting from y.
    hope that at some point we'll collide with the tame kangaroo's path
    '''
    xW = 0
    yW = y
    while xW < upperbound_exp - lowerbound_exp + xT:
        fW = f(yW)
        xW += fW
        yW = (yW * pow(g, fW, p)) % p
        '''
        check if we've gone past yT and missed it (didn't collide) 
        if we do, we'll eventually end up at the same place
        '''
        if yW == yT:
            # this return is the index of the input y
            return upperbound_exp + xT - xW


if __name__ == "__main__":

    ##########
    # PART 1 #
    ##########

    y = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119
    
    # find the index of y
    res = pollard(y, 0, 2 ** 20)

    print(f'Small example (2^20): {pow(g, res, p) == y}')

    # y = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733
    
    # # bigger k so that the kangaroo can jump further, which reduces running time  
    # res = pollard(y, 0, 2 ** 40, k=25)

    # print(f'Bigger one (2^40): {pow(g, res, p) == y}')


    ##########
    # PART 2 #
    ##########

    # same as challenge57
    factors = [2, 12457, 14741, 18061, 31193, 33941, 63803]
    prod = 2 * 12457 * 14741 * 18061 * 31193 * 33941 * 63803
    encryption_len = (p.bit_length() + 7) // 8
    msg = b"crazy flamboyant for the rap enjoyment"

    def get_mac(key: int, msg: bytes) -> bytes:
        return digest(key.to_bytes(encryption_len, 'big'), msg, 'md5')

    ''' bob's key
    secret = n [mod]
    public = g^secret
    '''
    secret = randrange(1, q)
    public = pow(g, secret, p)

    # remainder modulus `factors`
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

    print(f'Len(factors) = len(remainders)? {len(factors) == len(remainders)}')

    # do chinese remainder theorem
    recovered = 0
    for factor, remainder in zip(factors, remainders):
        factor_ = prod // factor
        inverse = mod_inv(factor_, factor)
        recovered = (recovered + remainder * inverse * factor_) % prod

    # y = g^x = g^(n + mr) = g^n + (g^r)^m
    m = pollard(
        (public * pow(g, q - recovered, p)) % p,
        0,
        q // prod,
        k = 22,
        g = pow(g, prod, p)
    )

    recoveredSecret = prod * m + recovered
    print(f'Recovered: {recoveredSecret}')
    print(f'Check: {recoveredSecret == secret}')