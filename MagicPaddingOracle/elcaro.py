#!usr/bin/python
#This is in Python 2.  Beware!
from pwn import *
context.log_level = 'error' #Hopefully makes things a bit more silent...
def connectme(send):
	r = remote('2018shell.picoctf.com',4966) #Different for every user, it seems.
	r.sendlineafter('What is your cookie?',send)
	s = r.recvrepeat(1)
	r.shutdown()
	return s.strip("\n")

def hexify(num):
	temp = hex(num)[2:]
	if len(temp)%2 !=0 :
		temp = '0' + temp
	return temp

def hex2blocks(h):
	if len(h) %2 !=0:
		h = '0' + h
	return [int(h[i:i+2],16) for i in range(0,len(h),2)]

def blocks2hex(b):
	hexes = [hexify(n) for n in b]
	return "".join(hexes)

def asciify(b):
	temp = [chr(c) for c in b]
	return "".join(temp)

def decrypt_block(cipherblock):
	intermediate_value = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	#Assuming AES-128
	for b in range(16): #128/8 = 16 bytes.
		print("Guessing byte # {}...".format(16-b))
		zero_pad = '0'*(30-(2*b))
		known_values = [hexify(intermediate_value[16-b+i]^(b+1)) for i in range(b)]
		known_values = "".join(known_values)
		for c in range(256):
			guess = hexify(c)
			# print("Guessing 0x{}....".format(cake))
			forgery = zero_pad + guess + known_values + cipherblock
			# print("Sending {}...".format(hex2blocks(zero_pad+guess+known_values)))
			if (c+1)%16 == 0:
				print("Trying {}...".format(c))
			#Send this forgery to the server!
			response = connectme(forgery)
			while response == '':
				print("Warning: Empty response received. Possible timeout error.")
				response = connectme(forgery)
			# print(response)
			padding_check = response.find('invalid padding')
			if padding_check == -1: #If this is not a padding error, put the intermediate value in...
				#...except if this is the first digit. In that case, do a sanity check first.
				print("Got it!")
				if b == 0:
					forgery = '000000000000000000000000000001' + guess + cipherblock
					response = connectme(forgery)
					#print(response)
					if response.find('invalid padding') == -1: #If the padding check does not fail, then we have 0x01 at the plaintext byte, as desired.
						intermediate_value[15] = c ^ (b+1)
						print("Stored {} XOR {} = {}".format(c,b+1,intermediate_value[15]))
						break
				else:
					intermediate_value[15-b] = c ^ (b+1)
					print("Stored {} XOR {} = {}".format(c,b+1,intermediate_value[15-b]))
					break
		else:
			raise ValueError("Match not found for byte # {}. Final value was {}".format(16-b,intermediate_value))
			break
	return intermediate_value

##The input I want
plaintext = '{"username": "guest", "expires": "2050-01-07", "is_admin": "true"}'
decrypted_block = [26, 92, 152, 152, 85, 219, 32, 140, 214, 141, 71, 54, 129, 236, 200, 90]
#Chop the plaintext into its ASCII values and determine the padding.
plaintext_array = [ord(c) for c in plaintext]
padding = 16 - len(plaintext_array)%16
plaintext_array.extend([padding for i in range(padding)])
#Begin determining what the 'cookie' should be like.
no_of_blocks = len(plaintext_array)/16
cookie = '4dfdacead33f1fdf0580901129a2ec56' #We will not change the final ciphertext block.
for block_no in range(no_of_blocks):
	print("Begin block #{}.".format(no_of_blocks-block_no))
	#Initialize values...
	block_start = (no_of_blocks - block_no -1) * 16
	plaintext_block = plaintext_array[block_start:block_start+16]
	print(asciify(plaintext_block)) #For debug purposes
	if block_no != 0:
		#If this is not the first block, figure out what the decryption is.
		decrypted_block = decrypt_block(blocks2hex(cipher_block))
	#When done, the ciphertext of the previous block is the XOR of the current plaintext block and the decrypted value.
	cipher_block = [decrypted_block[i] ^ plaintext_block[i] for i in range(16)] #Assuming AES-128
	#Append the hexification of the  new cipherblock to the cookie.
	cookie = blocks2hex(cipher_block) + cookie
	print("Current cookie: {}".format(cookie))
print(cookie)
getmetheflag = connectme(cookie)
print(getmetheflag)