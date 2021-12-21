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

#### <span style="color:red">5. RSA 1 - Weiner-Attack </span>

~~~
Statement: Find flag when know: 
Given: 
c = 0x217c8bf9b45601267624c3b1ba89ae93d04c8fae32dc15496262f36f48d06c0dc9e178a77b77a33708dcbe1fcd55ea9eb636fe5684c2f0f08df3389f47b36a128636671eba300491c829ed1e252b1bb4dbb3b93bc46d98a10bb5d55347752052ab45e143fd46799be1d06ac3ff7e8b1eb181dfbba8dfac3910202fd0b9a25befe
E = 266524484526673326121255015126836087453426858655909092116029065652649301962338744664679734617977550306567819672969837450223062478394149960243362563995235387971047857994699247277712682103161537347874310994510059329875060868679654080020041070975648626636209785889112656335054840517934593236597457100751820027783
N = 412460203584740978970185080155274765823237615982150661072746604041385717906706098256415230390148737678989448404730885157667896599397615737297545930957425615121654272472589331747646564634264520011009284080299605233265170506809736069720838542498970453928922703911186788239628906189362646418960560442406497717567
~~~

Solution:

~~~
Find d using Weiner-Attack
~~~

Code:

```py
from sage.all import Integer
from sage.all import continued_fraction

#from factorization import known_phi
n = 412460203584740978970185080155274765823237615982150661072746604041385717906706098256415230390148737678989448404730885157667896599397615737297545930957425615121654272472589331747646564634264520011009284080299605233265170506809736069720838542498970453928922703911186788239628906189362646418960560442406497717567
e = 266524484526673326121255015126836087453426858655909092116029065652649301962338744664679734617977550306567819672969837450223062478394149960243362563995235387971047857994699247277712682103161537347874310994510059329875060868679654080020041070975648626636209785889112656335054840517934593236597457100751820027783

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

Result:

```
d =  1
d =  2
d =  3
d =  27979163639208238097581493168255260980791785886427784936313524512033423912647
```
With every d we find, try find flag:

Code:

```py
from Crypto.Util.number import *
c_hex = "0x217c8bf9b45601267624c3b1ba89ae93d04c8fae32dc15496262f36f48d06c0dc9e178a77b77a33708dcbe1fcd55ea9eb636fe5684c2f0f08df3389f47b36a128636671eba300491c829ed1e252b1bb4dbb3b93bc46d98a10bb5d55347752052ab45e143fd46799be1d06ac3ff7e8b1eb181dfbba8dfac3910202fd0b9a25befe"
c = int(c_hex,16)
e = 266524484526673326121255015126836087453426858655909092116029065652649301962338744664679734617977550306567819672969837450223062478394149960243362563995235387971047857994699247277712682103161537347874310994510059329875060868679654080020041070975648626636209785889112656335054840517934593236597457100751820027783
n = 412460203584740978970185080155274765823237615982150661072746604041385717906706098256415230390148737678989448404730885157667896599397615737297545930957425615121654272472589331747646564634264520011009284080299605233265170506809736069720838542498970453928922703911186788239628906189362646418960560442406497717567

d = 27979163639208238097581493168255260980791785886427784936313524512033423912647

flag = long_to_bytes(pow(c,d,n))
print(flag)

```

Result:

```
b'Bugs_Bunny{Baby_Its_Cool_Lik3_school_haHAha}'
```

~~~
Note: Using flag.decode() the flag will be: Bugs_Bunny{Baby_Its_Cool_Lik3_school_haHAha}
~~~

#### <span style="color:red">6. RSA 2 - RsaCtfTool </span>

~~~
Given:
c = 24069342720029447645279421073270575353047711895242659815039311355734342330508297195320032629315218226212387151445283779967345116103626286184366740272344305727987474407741946014932936418366083000851440285481560035222386750756966859
e = 65537
n= 1230186684530117755130494958384962720772853569595334792197322452151726400507263657518745202199786469389956474942774063845925192557326303453731548268507917026122142913461670429214311602221240479274737794080665351419597459856902143413
~~~

~~~
Find flag using RsaCtfTool
~~~

~~~
Solve:
~~~

1. Download in [here](https://github.com/Ganapati/RsaCtfTool)

2. Using Kali to solve:

~~~
python3 RsaCtfTool.py -n 1230186684530117755130494958384962720772853569595334792197322452151726400507263657518745202199786469389956474942774063845925192557326303453731548268507917026122142913461670429214311602221240479274737794080665351419597459856902143413 -e 65537 --uncipher 24069342720029447645279421073270575353047711895242659815039311355734342330508297195320032629315218226212387151445283779967345116103626286184366740272344305727987474407741946014932936418366083000851440285481560035222386750756966859
~~~

~~~
Flag: tpctf{omg_b1c_m0dulus}
~~~

![Imgur](https://i.imgur.com/3kBExVy.png)

#### <span style="color:red">7. RSA 3 - rshack </span>

~~~
Given:
n = 744818955050534464823866087257532356968231824820271085207879949998948199709147121321290553099733152323288251591199926821010868081248668951049658913424473469563234265317502534369961636698778949885321284313747952124526309774208636874553139856631170172521493735303157992414728027248540362231668996541750186125327789044965306612074232604373780686285181122911537441192943073310204209086616936360770367059427862743272542535703406418700365566693954029683680217414854103

e = 57595780582988797422250554495450258341283036312290233089677435648298040662780680840440367886540630330262961400339569961467848933132138886193931053170732881768402173651699826215256813839287157821765771634896183026173084615451076310999329120859080878365701402596570941770905755711526708704996817430012923885310126572767854017353205940605301573014555030099067727738540219598443066483590687404131524809345134371422575152698769519371943813733026109708642159828957941

c = 305357304207903396563769252433798942116307601421155386799392591523875547772911646596463903009990423488430360340024642675941752455429625701977714941340413671092668556558724798890298527900305625979817567613711275466463556061436226589272364057532769439646178423063839292884115912035826709340674104581566501467826782079168130132642114128193813051474106526430253192254354664739229317787919578462780984845602892238745777946945435746719940312122109575086522598667077632
~~~

You can download tool in [here](https://github.com/zweisamkeit/RSHack)


![Imgur](https://i.imgur.com/5S0Fq4X.png)

So we get:

~~~
d = 108642162821084938181507878056324903120999504739411128372202198922197750954973
~~~

Now, flag is:

~~~
flag = pow(c,d,n)
~~~

Result is:

![Imgur](https://i.imgur.com/qXkFXwQ.png)

~~~
Flag: d4rk{r3p34t3ed_RsA_1s_f0r_n00bs}
~~~

#### <span style="color:red">7. RSA 4 - Tool online </span>

~~~
Given:

- ciphertext (base64): PePAW8C9Lm7yxsyA2MShozuHpDrRZJssZECWAYULMEMq7pfcX4cUyKpWvW8ZVQis+KtxT7pa1LEcq4UvYW8Gm44nTUwPOOzqw86MXonJ8Mwgx9gXlZHNReG/X2+bynejQo36b1axIt9RujXCxXzEsOzO/gpSVE24bgvwwvU+C28= 

- public key :
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCO5+gAGMWkPvEtXWLRaqxSm3PeNtMMDfbGQs15Gms7trqxGnK+pjZslc4oVyw6cu5RHrt4YpfGY1VeXG8ZeIiY5BagA7eMP8Rv5ixblyhA51MMDNd/+gNcDZH4MvtM1KsDYYeeD9SXKrBI10znG7nxV4fAB39Y4PW8UzMv8GFVEQIDAQAB
~~~

Using this [website](https://www.devglan.com/online-tools/rsa-encryption-decryption) and choose mode `public key`

Result is:

![Imgur](https://i.imgur.com/TuxNbjk.png)

Flag:

~~~
Flag: SBCTF{53cu23_data_724n5m15510n}
~~~

#### <span style="color:red">8. RSA 5 - Three file pub </span>


Given:
- file `bob.pub`

~~~
-----BEGIN PUBLIC KEY-----
MDgwDQYJKoZIhvcNAQEBBQADJwAwJAIdDVZLl4+dIzUElY7ti3RDcyge0UGLKfHs
+oCT2M8CAwEAAQ==
-----END PUBLIC KEY-----
~~~
- file `bob2.pub`

~~~
-----BEGIN PUBLIC KEY-----
MDgwDQYJKoZIhvcNAQEBBQADJwAwJAIdCiM3Dn0PsAIyFkrG1kKED8VOkgJDP5J6
YOta29kCAwEAAQ==
-----END PUBLIC KEY-----

~~~

- file `bob3.pub`

~~~
-----BEGIN PUBLIC KEY-----
MDgwDQYJKoZIhvcNAQEBBQADJwAwJAIdDFtp4ZeeVB+F2s3iqhTSciqEb0Gz24Pm
Z+Oz0R0CAwEAAQ==
-----END PUBLIC KEY-----
~~~

- file `secret.enc`

~~~
DK9dt2MTybMqRz/N2RUMq2qauvqFIOnQ89mLjXY=

AK/WPYsK5ECFsupuW98bCFKYUApgrQ6LTcm3KxY=

CiLSeTUCCKkyNf8NVnifGKKS2FJ7VnWKnEdygXY=
~~~

Solution:

Using:

~~~
from Crypto.PublicKey import RSA

f = open('bob.pub', 'r')
pubkey = RSA.import_key(f.read())

print("n = ", pubkey.n)
print("e = ", pubkey.e)
~~~

And use this [link](https://www.alpertron.com.ar/ECM.HTM) to factorizer a number

`Part 1:`

~~~
n = 359567260516027240236814314071842368703501656647819140843316303878351
e = 65537
p =  17963604736595708916714953362445519
q =  20016431322579245244930631426505729
phi_n = (p-1)*(q-1)
d = inverse(e,phi_n)
c_base64 = DK9dt2MTybMqRz/N2RUMq2qauvqFIOnQ89mLjXY=
~~~

`Part 2:`

~~~
n = 273308045849724059815624389388987562744527435578575831038939266472921
e = 65537
p = 16514150337068782027309734859141427
q = 16549930833331357120312254608496323
phi_n = (p-1)*(q-1)
d = inverse(e,phi_n)
c_base64 = CiLSeTUCCKkyNf8NVnifGKKS2FJ7VnWKnEdygXY=
~~~

`Part 3:`

~~~
n = 333146335555060589623326457744716213139646991731493272747695074955549
e = 65537
p = 17357677172158834256725194757225793
q = 19193025210159847056853811703017693
phi_n = (p-1)*(q-1)
d = inverse(e,phi_n)
c_base64 = AK/WPYsK5ECFsupuW98bCFKYUApgrQ6LTcm3KxY=
~~~

Solution:

```py
from Crypto.PublicKey import RSA 
from Crypto.Util.number import *
from base64 import b64decode


# First process

# f = open('bob3.pub', 'r')
# pubkey = RSA.import_key(f.read())

# print("n = ", pubkey.n)
# print("e = ", pubkey.e)

# Second process
## Part 1

# n = 359567260516027240236814314071842368703501656647819140843316303878351
# e = 65537
# p = 17963604736595708916714953362445519
# q = 20016431322579245244930631426505729
# phi_n = (p-1)*(q-1)
# d = inverse(e,phi_n)
# c_base64 = "DK9dt2MTybMqRz/N2RUMq2qauvqFIOnQ89mLjXY="
# c = bytes_to_long(b64decode(c_base64))
# flag = long_to_bytes(pow(c,d,n))
# print(flag)

# Ans 1: IW{WEAK_R

## Part 2
# n = 273308045849724059815624389388987562744527435578575831038939266472921
# e = 65537
# p = 16514150337068782027309734859141427
# q = 16549930833331357120312254608496323
# phi_n = (p-1)*(q-1)
# d = inverse(e,phi_n)
# c_base64 = "CiLSeTUCCKkyNf8NVnifGKKS2FJ7VnWKnEdygXY="
# c = bytes_to_long(b64decode(c_base64))
# flag = long_to_bytes(pow(c,d,n))
# print(flag)

# Ans 2: SA_K3YS_4R

## Part 3 
# n = 333146335555060589623326457744716213139646991731493272747695074955549
# e = 65537
# p = 17357677172158834256725194757225793
# q = 19193025210159847056853811703017693
# phi_n = (p-1)*(q-1)
# d = inverse(e,phi_n)
# c_base64 = "AK/WPYsK5ECFsupuW98bCFKYUApgrQ6LTcm3KxY="
# c = bytes_to_long(b64decode(c_base64))
# flag = long_to_bytes(pow(c,d,n))
# print(flag)

# # Ans 3: _SO_BAD!}

# FLAG : IW{WEAK_RSA_K3YS_4R_SO_BAD!}
```

~~~
Flag: IW{WEAK_RSA_K3YS_4R_SO_BAD!}
~~~

#### <span style="color:red">9. RSA 6 - File PEM </span>

Given:

`public.pem`

~~~

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEBITsFfW/evEUntbdCGsHp
PM/+p2xPCHSZHPP6zw6rnvZGohg5ggtNZTqRa2jyWOnT98K6BU5K8F8+TWGz3nct
KtIziw6ubqCPIHbk5LCKsgkg+miF5sRN7BvuKKh2U8dLy56fEpTeiki9YUZSo9ZZ
3857iURhDyW/r5NumlQWfE0ifRbTLmXqRYtp1g3s1/oDTBs72GJxcWTneF6wbcxb
iLqiYuQxIOVGZcDLyz6tUbCgCBm06R1IctP753JOA6txvK+LuEx03slqrfyxhlOo
8FOT1mYGmSO8e5sxNj1tbZtFn0bbW6+W+EBKrxqDHw24qtfZOkJW6BVrK3B1egEg
kwIDAQAB
-----END PUBLIC KEY-----
~~~

`flag.enc`

~~~
Cc0GtEY4nL7DhDukClWKaTHChrCVJeVVm3MJ+6hgiqaYUjbx9ArCrH0uzdfDqf4l81NAqV0fGtd8a9H4dlEQRykvOwpFpViK4qTU1H28nEMZ6O1Hnt9NrLxlSvpARZd8hxoJtXiwUbZI6rcI9lQwt+pJLvrvw2/Mz+fBMvrVPFONSYDH/lU0wy4jKbH0zl7zJ09+gCBo9oJ2Hqpsh0BkcS6ix5lDu/6JENG/ChC7jZGYWpte+QIkb/fQTwsw3tGIz1jWYhqQ8MrSxtGpyyPG9Oy/zGHIBEBDesS4r72D8n2mQExRnCH2KW5wz5hsM2TXYRILtJqWCOyv/AF56Ebg9A==
~~~

`Solution`

- Step 1: Find `n,e,c`

```py
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from base64 import b64decode 

f = open("public.pem","r")
public = RSA.import_key(f.read())
n = public.n 
e = public.e
print("n = ",public.n)
print("e = ",public.e)
c_base64 = "Cc0GtEY4nL7DhDukClWKaTHChrCVJeVVm3MJ+6hgiqaYUjbx9ArCrH0uzdfDqf4l81NAqV0fGtd8a9H4dlEQRykvOwpFpViK4qTU1H28nEMZ6O1Hnt9NrLxlSvpARZd8hxoJtXiwUbZI6rcI9lQwt+pJLvrvw2/Mz+fBMvrVPFONSYDH/lU0wy4jKbH0zl7zJ09+gCBo9oJ2Hqpsh0BkcS6ix5lDu/6JENG/ChC7jZGYWpte+QIkb/fQTwsw3tGIz1jWYhqQ8MrSxtGpyyPG9Oy/zGHIBEBDesS4r72D8n2mQExRnCH2KW5wz5hsM2TXYRILtJqWCOyv/AF56Ebg9A=="
c = long_to_bytes(b64decode(c_base64))
```

- Step 2: Using [factorize](https://www.alpertron.com.ar/ECM.HTM) to factorize `n`, we have `n` is prime, so `phi(n)=n-1`. Then we have `d = inverse(e,phi(n))` and `flag = pow(c,d,n)`

`Total code:`

```py
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from base64 import b64decode 

f = open("public.pem","r")
public = RSA.import_key(f.read())
n = public.n 
e = public.e
print("n = ",public.n)
print("e = ",public.e)
c_base64 = "Cc0GtEY4nL7DhDukClWKaTHChrCVJeVVm3MJ+6hgiqaYUjbx9ArCrH0uzdfDqf4l81NAqV0fGtd8a9H4dlEQRykvOwpFpViK4qTU1H28nEMZ6O1Hnt9NrLxlSvpARZd8hxoJtXiwUbZI6rcI9lQwt+pJLvrvw2/Mz+fBMvrVPFONSYDH/lU0wy4jKbH0zl7zJ09+gCBo9oJ2Hqpsh0BkcS6ix5lDu/6JENG/ChC7jZGYWpte+QIkb/fQTwsw3tGIz1jWYhqQ8MrSxtGpyyPG9Oy/zGHIBEBDesS4r72D8n2mQExRnCH2KW5wz5hsM2TXYRILtJqWCOyv/AF56Ebg9A=="
c = bytes_to_long(b64decode(c_base64))
print("c = ",c)
phi_n = n-1 
d = inverse(e,phi_n)
flag = long_to_bytes(pow(c,d,n))
print(flag)
```

~~~
Flag: Flag{S1nGL3_PR1m3_M0duLUs_ATT4cK_TaK3d_D0wn_RSA_T0_A_Sym3tr1c_ALg0r1thm} 
~~~

#### <span style="color:red">10. RSA 7 - Round Rabin </span>

Given 

```
n = 0x6b612825bd7972986b4c0ccb8ccb2fbcd25fffbadd57350d713f73b1e51ba9fc4a6ae862475efa3c9fe7dfb4c89b4f92e925ce8e8eb8af1c40c15d2d99ca61fcb018ad92656a738c8ecf95413aa63d1262325ae70530b964437a9f9b03efd90fb1effc5bfd60153abc5c5852f437d748d91935d20626e18cbffa24459d786601
e = 2
c = 0xd9d6345f4f961790abb7830d367bede431f91112d11aabe1ed311c7710f43b9b0d5331f71a1fccbfca71f739ee5be42c16c6b4de2a9cbee1d827878083acc04247c6e678d075520ec727ef047ed55457ba794cf1d650cbed5b12508a65d36e6bf729b2b13feb5ce3409d6116a97abcd3c44f136a5befcb434e934da16808b0b
```

Require: `Find flag`

`Step 1` : Convert `n,c` into decimal

```py
n = "0x6b612825bd7972986b4c0ccb8ccb2fbcd25fffbadd57350d713f73b1e51ba9fc4a6ae862475efa3c9fe7dfb4c89b4f92e925ce8e8eb8af1c40c15d2d99ca61fcb018ad92656a738c8ecf95413aa63d1262325ae70530b964437a9f9b03efd90fb1effc5bfd60153abc5c5852f437d748d91935d20626e18cbffa24459d786601"
c = "0xd9d6345f4f961790abb7830d367bede431f91112d11aabe1ed311c7710f43b9b0d5331f71a1fccbfca71f739ee5be42c16c6b4de2a9cbee1d827878083acc04247c6e678d075520ec727ef047ed55457ba794cf1d650cbed5b12508a65d36e6bf729b2b13feb5ce3409d6116a97abcd3c44f136a5befcb434e934da16808b0b"
nn = int(n,16)
cc = int(c,16)
```

`Step 2` : Using [factorize big number online](https://www.alpertron.com.ar/ECM.HTM) we found that: `n=p*p`

Using this algorithm to find `p`:

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
nn = 75404462446621433278932073418166377856783371695311741162660984000216286022717332034344886883228963555598915581623574177254937709767805818855313080010310907057693076782794571905025544034519430835894406844610021327070351428935856401291946497064114909504725588880164068827953784803548706132824333011073782801921
print(isqrt(nn))
```

Result: `p=8683574289808398551680690596312519188712344019929990563696863014403818356652403139359303583094623893591695801854572600022831462919735839793929311522108161`

Now, we will find research some bit knowledge about `Quadratic residue`

In number theory, an interger q is called a quadratic residue module n if it is congruent to a perfect square modulo n; i.e if there exists an integer x such that `x^2=q(mod n)`.

Otherwise, q is called a quadratic nonresidue modulo n.

Next, we will get familiar with `Legendre Symbol`

In Legendre symbol we introduced a fast way to determine whether a number is a square root modulo a prime. We can go further: there are algorithms for efficiently calculating such roots. The best one in practice is called `Tonelli-Shanks`, which gets its funny name from the fact that is was first described by an Italian in the 19th century and rediscovered independently by Daniel Shanks in the 1970s.

All primes that aren't `2` are of the form `p=1 (mod 4)` or `p=3 (mod 4)`, since all odd numbers obey these congruences. As the previous challenge hinted, in the `p=3 (mod 4)` case, a really simple formula for computing square roots can be derived directly from Fermat's little theorem. That leaves us still with the `p=1(mod 4)` case, so a more general algorithm is required.

In a congruence of the form `r^2 = a(mod p)`, `Tonelli-Shanks` calculates `r`

Note: Tonelli-Shanks doesn't work for composite(non-prime) moduli. Finding square roots modulo composites is computationally equivalent to integer factorization.

Next, we will have research `Legendre symbol`:

![Imgur](https://i.imgur.com/KWKAnvv.png)

And some characteristic of this:

![Imgur](https://i.imgur.com/lt4lOia.png) 

and last is example:

![Imgur](https://i.imgur.com/VnfJGDh.png) 

Another we can reference some special symbols such as: [Jacobi symbol](https://vi.wikipedia.org/wiki/K%C3%BD_hi%E1%BB%87u_Jacobi) and [Kronecker Symbol](https://en.wikipedia.org/wiki/Kronecker_symbol)

Continued: [P1](https://cryptohack.org/challenges/maths/) and [P2](https://en.wikipedia.org/wiki/Rabin_cryptosystem) and [P3](https://github.com/WCSC/writeups/tree/master/icectf-2016/Round-Rabins)























