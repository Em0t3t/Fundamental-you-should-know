# How we can use some amazing pwnable tools :xD

## 1. gcc
- Compile C program to the binary file.
- Normal and recommended usage:
	```sh
	gcc code.c -o binary
	``` 
- Advanced usage:
	+ Disable Canary: **-fno-stack-protector**
	+ Disable NX: **-z execstack**
	+ Disable/Enable PIE: **-no-pie/-pie**
	+ Disable RELRO: **-Wl,-z,norelro**
	+ Partial RELRO: **-Wl,-z,relro**
	+ Full RELRO: **-Wl,-z,relro,-z,now**
	+ Strip: **-s**
	+ ELF 32bit: **-m32**
		```sh
		sudo apt-get install gcc-multilib
		```
	+ Statically linked: **-static**

## 2. gdb-peda
- CLI debug tool
- [Install guide](https://github.com/longld/peda)
- Usage:
	| Command | Meaning |
	|---------|---------|
	| **checksec** | Check for the security options of binary |
	| **start** | Make gdb run the binary and stop in main |
	| **br\*** 0x401420 | Set a break point at 0x401420 |
	| **run/r** | Run the program from the begining |
	| **continue/c** | Run the program from the current instruction |
	| **next/n** | Run the current instruction and stop at the next one |
	| **info register** | Check value of all the register |
	| **info breakpoints** | Check breakpoints that has been set |
	| **del 1** | Delete the breakpoint at the 1st position |
	| **pdisass functionname/address** | Display assembly code of a function or from an address |
	| **x/...** | [Read more here](https://visualgdb.com/gdbreference/commands/x) |
	| **vmmap** | Check all memory areas of the process |
	| **find 0x123/abcd/...** | Find the address of that search value in the process |
	| **stack n** | Show stack in n line |
	| **set $rdi=2** | Set a value for a register |
	| **set \*0x404020=0x1234** | Set 4 bytes from the address 0x404020 with value of 0x1234 | 
	| **print main/&__malloc_hook/...** | Show address of a symbol |

## 3. Pwntools (python3)
- CTF framework and exploit development library.
- [Documentation](https://github.com/Gallopsled/pwntools)
- Some notes:
	+ Debug in local process:
		```python3
		r = process("./binary")
		gdb.attach(r)
		r.interactive()	
		```
	+ Convert bytes to int (python itself actually :vv):
		```python3
		int.from_bytes(b'abcd', 'little')
		```
	+ Convert assembly to shellcode:
		```python3
		shellcode = """
		mov rdi, 0x67616c66
		mov rsi, {}
		""".format(buf+0x100)		
		shellcode = asm(shellcode, arch = 'amd64', os = 'linux')
		```
	+ Find address of some symbol in libc file:
		```python3
		libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
		libc.address = libc_leak - 0x1ebbe0
		free_hook = libc.sym['__free_hook']
		system = libc.sym['system']
		binsh = next(libc.search(b'/bin/sh\x00'))
		```
	+ Find address of some symbol in binary file:
		```python3
		e = ELF('/bin/cat')
		e.address # 0x400000
		e.symbols['write']
		e.got['write']
		e.plt['write']
		```

## 4. objdump
- Usage **objdump <options> <file>**:
	+ **-R** : Display GOT Table (dynamically linked)
	+ **-d -Mintel** : Display assembly code in executable sections with Intel syntax

## 5. readelf
- Usage: **readelf <options> <file>**:
	+ **-s**: Display address offset of symbol in ELF file

## 6. strings
- Usage: **strings <options> <file>**:
	+ **-tx**: Print the location of the string in hex format. Example:
		```sh
		strings -tx /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
		```

## 7. ROPgadget
- Display the gadget and its offset address in the binary file
- Example: 
	```sh
	ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6
	```

## 8. one_gadget
- Display the offset address of execve("/bin/sh") with the constraints in the binary file.
- Example:
	
	![image](https://i.ibb.co/W0rKNgg/pwn-tool-1.png)

## 9. ldd
- Find which library file will be loaded when the binary runs
- Example:
	
	![image](https://i.ibb.co/CvQ2KQH/pwn-tool-2.png)

## 10. patchelf
- Set the custom library file for the binary
- Example:
	```sh
	patchelf --set-interpreter ./ld-2.32.so --add-needed ./libc.so.6 ./mybinary
	```
- Now the binary file **mybinary** will use the custom library file **libc.so.6** instead of the default library file **/lib/x86_64-linux-gnu/libc.so.6**.
