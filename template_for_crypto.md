### TEMPLATE CRYPTO

####  <span style="color:red">1. TÌM CĂN BẬC HAI</span> 

```py
import math

_1_50 = 1 << 50  # 2**50 == 1,125,899,906,842,624
def isqrt(x):
    """Return the integer part of the square root of x, even for very
    large integer values."""
    if x < 0:
        raise ValueError('square root not defined for negative numbers')
    if x < _1_50:
        return int(math.sqrt(x))  # use math's sqrt() for small parameters
    n = int(x)
    if n <= 1:
        return n  # handle sqrt(0)==0, sqrt(1)==1
    # Make a high initial estimate of the result (a little lower is slower!!!)
    r = 1 << ((n.bit_length() + 1) >> 1)
    while True:
        newr = (r + n // r) >> 1  # next estimate by Newton-Raphson
        if newr >= r:
            return r
        r = newr
```

#### <span style="color:red">2. READFILE BYTES PYTHON</span> 

```py
from Crypto.Util.number import *
f = open("chall.enc", "rb")
ans = bytes_to_long(f.read())
print(ans)
```

#### <span style="color:red">3. WEINER ATTACK </span> 

```py
from sage.all import Integer
from sage.all import continued_fraction

#from factorization import known_phi
n = 17729028558979019485846420034614601781855286885772116033115998289130663218793249135103097941406615594783564487056148202535602218241261076180277862184340050681277512936764254998557657989633659561175844653871375735119626199870178796372816549333367076487655787617921785826120525919291798195591267544750350222858119219959311035913906885739352404726672836723117136379411134589884489391116922923390687958161705756705708668649262568471831705504852664779788943978721769038284989250803324876493071615384204553854811020877754034576798208169454695001947778015807032019651748938505463608871771494765303144219873993106068807291321
e = 65537

def attack(n, e):
    """
    Recovers the prime factors of a modulus and the private exponent if the private exponent is too small.
    :param n: the modulus
    :param e: the public exponent
    :return: a tuple containing the prime factors of the modulus and the private exponent, or None if the private exponent was not found
    """
    convergents = continued_fraction(Integer(e) / Integer(n)).convergents()
    for c in convergents:
        k = c.numerator()
        d = c.denominator()
        if k == 0 or (e * d - 1) % k != 0:
            continue

        print("d",d)
attack(n,e)
```

~~~
Note: Run on linux
~~~

#### <span style="color:red">4. READ FILE .PEM TO FIND N AND E IN RSA </span>

```py
f = open('public.pem','r')
key = RSA.importKey(f.read())
print("n: ",key.n)
print("e: ",key.e)
```








