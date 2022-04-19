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

####  <span style="color:red">2. TÌM CỜ TRONG FILE BINARY</span>

Link problem: [THE MORE THE MERRIER](https://247ctf.com/dashboard)

![Imgur](https://i.imgur.com/uCMPkT4.png) 

Và công việc lúc này ta chỉ cần sử dụng python để viết một đoạn code đơn giản nhằm loại bỏ các khoảng trống không cần thiết để thu được cờ:

![Imgur](https://i.imgur.com/1bocA6h.png)

`Flag: 247CTF{6df215eb3cc73407267031a15b0ab36c}`

####  <span style="color:red">3. picoCTF - file-run1</span>

LINK PROBLEM: [file-run1](https://play.picoctf.org/practice/challenge/266?category=3&originalEvent=70&page=1&solved=0)

Bài này sau khi tải file `run` về, click chuột và chọn mở bằng `notepad`

Sau đó, mở bằng Text Editor, tìm kiếm với từ khoá `pico`, ta thu được:

~~~
picoCTF{U51N6_Y0Ur_F1r57_F113_e5559d46}
~~~

####  <span style="color:red">4. picoCTF - file-run2</span>

LINK PROBLEM: [file-run2](https://play.picoctf.org/practice/challenge/267?category=3&originalEvent=70&page=1&solved=0)

Bài này tương tự bài `file-run1`, ta cũng sẽ thu được 

~~~
picoCTF{F1r57_4rgum3n7_96f2195f}
~~~

####  <span style="color:red">5. picoCTF - GDB Test Drive </span>

Để thực hiện được các thao tác liệt kê trong description, ta nên sử dụng hệ điều hành Linux, ở đây mình sử dụng Kali Linux

Tiếp theo ta sẽ tải file đó về, và thực hiện các bước như phần mô tả đã trình bày

```
chmod +x gdbme
gdb gdbme
(gdb) layout asm
(gdb) break *(main+99)
(gdb) run
(gdb) jump *(main+104)
```

Link thực hiện: [Solution](https://youtu.be/-2wOYw9t4eg)