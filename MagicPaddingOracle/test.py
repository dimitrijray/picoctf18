from pwn import *
def connectme(send):
	r = remote('2018shell.picoctf.com',4966)
	r.sendlineafter('What is your cookie?',send)
	s = r.recvrepeat(1)
	r.shutdown()
	return s.strip("\n")

f = connectme('0000000000000000000000000000005b4dfdacead33f1fdf0580901129a2ec55')
print (f.find('invalid padding'))