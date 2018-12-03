#!/usr/bin/python
# -*- coding: utf-8 -*-
"""

@author: Dimitrij Ray
"""
#This is in Python 2.
from pwn import *
from math import ceil
import base64
import struct

def connectme(to_send):
	r = remote('2018shell.picoctf.com',31123)
	r.sendlineafter(': ',to_send)
	s = r.recvrepeat(5)
	r.shutdown()
	#print(s)
	return [s[i:i+32] for i in range(0,len(s),32)]

# print(connectme('00000000000'+'1'*40))

#Connect with the shell server.
r = remote('2018shell.picoctf.com',61333)
#Step 1: Get the filename of the flag. Compute its length, without the '.txt'
r.sendlineafter('Please choose: ','i')
s = r.recvline_regex('flag(.*)txt')
flag_fname = s.replace(' ','')
print(flag_fname)
fname_length = len(flag_fname)-4
#Convert the entirety of the filename to hex for easier storing.
flag_fname_hex = flag_fname.encode('hex')
#Step 2: Retrieve the encrypted IV by creating a file with known filename as long as the flag file.
fname_to_send = '0'*fname_length
actual_fname = fname_to_send + '.txt'
print(actual_fname)
afname_hex = actual_fname.encode('hex')
print(afname_hex)
r.sendlineafter('Please choose: ','n')
r.sendlineafter('Name of file? ',fname_to_send)
r.sendlineafter('Data? ','uh')
s = r.recvlines(2)
ciphertext = s[1] #Just grab the second line...
print(ciphertext)
cipher_in_hex = base64.b64decode(ciphertext).encode('hex') #Just to be sure...
print(cipher_in_hex)
#Do your magic! What is the IV?
counter = int(afname_hex,16)^int(cipher_in_hex,16)
#Step 3: AES magic time!
#XOR the IV with the flag filename.
sharecode_int = counter ^ int(flag_fname_hex,16)
sharecode = hex(sharecode_int)
sharecode = sharecode[2:]
print(sharecode)
sharecode_bytes = sharecode.decode('hex')
print(sharecode_bytes)
sharecode_b64 = base64.b64encode(sharecode_bytes)
print(sharecode_b64)
r.sendlineafter('Please choose: ','e')
r.sendlineafter('Share code? ',sharecode_b64)
s = r.recvrepeat(1)
print(s)
r.shutdown()