### TEMPLATE REVERSE

####  <span style="color:red">1. DÙNG PYTHON ĐỂ VIẾT CHƯƠNG TRÌNH THỰC THI CODE ASSEMBLY</span> 

`Given: TRX = "GED\x03hG\x15&Ka =;\x0c\x1a31o*5M"` and `DRX = ""` and `crypto.asm`

```py
MOV DRX "LemonS"
XOR TRX DRX
MOV DRX "caviar"
REVERSE DRX
XOR TRX DRX
REVERSE TRX
MOV DRX "vaniLla"
XOR TRX DRX
REVERSE TRX
XOR TRX DRX
REVERSE TRX
MOV DRX "tortillas"
XOR TRX DRX
MOV DRX "applEs"
XOR TRX DRX
MOV DRX "miLK"
REVERSE DRX
XOR TRX DRX
REVERSE TRX
XOR TRX DRX
REVERSE TRX
REVERSE TRX
REVERSE TRX
XOR DRX DRX
XOR TRX DRX
MOV DRX "OaTmeAL"
XOR TRX DRX
REVERSE TRX
REVERSE TRX
REVERSE TRX
XOR DRX DRX
XOR TRX DRX
MOV DRX "cereal"
XOR TRX DRX
MOV DRX "ICE"
REVERSE DRX
XOR TRX DRX
MOV DRX "cHerries"
XOR TRX DRX
REVERSE TRX
XOR TRX DRX
REVERSE TRX
MOV DRX "salmon"
XOR TRX DRX
MOV DRX "chicken"
XOR TRX DRX
MOV DRX "Grapes"
REVERSE DRX
XOR TRX DRX
REVERSE TRX
XOR TRX DRX
REVERSE TRX
MOV DRX "caviar"
REVERSE DRX
XOR TRX DRX
REVERSE TRX
MOV DRX "vaniLla"
XOR TRX DRX
REVERSE TRX
XOR TRX DRX
MOV DRX TRX
MOV TRX "HonEyWheat"
XOR DRX TRX
MOV TRX DRX
MOV DRX "HamBurgerBuns"
REVERSE DRX
XOR TRX DRX
REVERSE TRX
XOR TRX DRX
REVERSE TRX
REVERSE TRX
REVERSE TRX
XOR DRX DRX
XOR TRX DRX
MOV DRX "IceCUBES"
XOR TRX DRX
MOV DRX "BuTTeR"
XOR TRX DRX
REVERSE TRX
XOR TRX DRX
REVERSE TRX
MOV DRX "CaRoTs"
XOR TRX DRX
MOV DRX "strawBerries"
XOR TRX DRX
```

And my duty is write emulator to compile this asm code !

Solution:

```py
class Register:
    def __init__(self,value="") -> None:
        self.value=value

def xor_pwn(a,b):
    res=b''
    if len(a)>len(b):
        dest,src=a,b
    else:
        dest,src=b,a
    for i in range(len(src)):
        res+=chr((dest[i])^(src[i])).encode()
    for j in range(len(src),len(dest)):
        res+=chr(dest[j]).encode()
    return res

def mov(dest:Register,source):
    if type(source)==str:
        dest.value=source.encode()
    else:
        dest.value=source.value
def xor(dest:Register,source):
    if type(source)==str:
        dest.value=xor_pwn(dest.value,source.encode())
    else:
        dest.value=xor_pwn(dest.value,source.value)
def reverse(dest):
    dest.value=dest.value[::-1]

TRX = Register(b"GED\x03hG\x15&Ka =;\x0c\x1a31o*5M")
DRX = Register()
codelines=open("Crypto.asm","r").read().splitlines()

for codeline in codelines:
    dest=codeline.split()[1]
    if dest=="TRX":
        dest=TRX
    else:
        dest=DRX
    if len(codeline.split())>2:
        src=codeline.split()[2]
        if '"' in src:
            src=src.replace('"','')
        elif src=="TRX":
            src=TRX
        else:
            src=DRX
    if codeline.startswith("MOV "):
        mov(dest,src)
    elif codeline.startswith("XOR "):
        xor(dest,src)
    elif codeline.startswith("REVERSE "):
        reverse(dest)
print(TRX.value)
```

`Flag: flag{N1ce_Emul8tor!1}`