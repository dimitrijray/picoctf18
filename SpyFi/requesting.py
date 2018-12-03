#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""

@author: Dimitrij Ray
"""
#This is in Python 2.
from pwn import *
from math import ceil

def connectme(to_send):
	r = remote('2018shell.picoctf.com',31123)
	r.sendlineafter(': ',to_send)
	s = r.recvrepeat(5)
	r.shutdown()
	#print(s)
	return [s[i:i+32] for i in range(0,len(s),32)]

# print(connectme('00000000000'+'1'*40))

#Connect with the shell server...
flag = 'picoCTF{'
test_string = 'de is: picoCTF{'
for guess in range(31):#Guess the 31 characters before the flag.
	ones = 40-guess
	line_to_send = '00000000000' + '1'*ones
	one_blocks = int(ceil(ones/16))
	block_to_check = 8
	dummy = connectme(line_to_send)
	# print(block_to_check)
	block_to_match = dummy[block_to_check]
	# print("Block to match: {}".format(block_to_match))
	#Let the guessing game begin...
	for char in range(33,127):
		alpha = chr(char)
		line_to_send = '00000000000' + test_string + alpha
		# print("Sending {}".format(line_to_send))
		dummy = connectme(line_to_send)
		block_of_guess = dummy[4]
		if block_to_match == block_of_guess:
			print("Match found.")
			flag += alpha
			test_string +=alpha
			test_string = test_string[1:]
			break
	else:
		print("Match not found for guess: {}".format(guess))
		break
print(flag)