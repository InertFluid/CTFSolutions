from pwn import *

flag =''
passchar = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=+[]{|};":,.<>?/`~!@#$%^&*()'
padding = 'A'*16
sitrep = 'AAAAAidentifying code is: '
count = 0
while(1):
	for i in passchar:
		r = remote('2018shell.picoctf.com', 34490)
		if count==0:
			exploit = sitrep[:] + flag + i + padding[:]
		else:
			exploit = sitrep[:] + flag + i + padding[:-count]
			exploit = exploit[count:]				
		r.sendline(exploit)
		cip = r.recvall()[56:-1]
		if cip[32*4:32*4+32]==cip[32*4+32*3:32*4+32*4]:
			flag += i
			break
		if cip[32*4+32:32*4+32*2]==cip[32*4+32*4:32*4+32*5]:
			flag +=i
			break	
	if i==')':
		break
	if len(flag)==16:
		break					
	count += 1
	print '\n\n'+flag +'\n\n'

sitrep = 'AAAAAAidentifying code is: '
padding = 'A'*32
count = 0	
while(1):
	for i in passchar:
		r = remote('2018shell.picoctf.com', 34490)
		if count==0:
			exploit = sitrep[:] + flag[1:] + i + padding[:]	
		else:
			exploit = sitrep[:] + flag[count + 1:] + i + padding[:-count]
		r.sendline(exploit)
		cip = r.recvall()[56:-1]
		if cip[32*5:32*5+32]==cip[32*9+32:32*9+32*2]:
			flag += i
			break
	if flag[-1:]=='}':
		print '\n\n'+flag +'\n\n'	
		break	
	count += 1
	print '\n\n'+flag +'\n\n'
