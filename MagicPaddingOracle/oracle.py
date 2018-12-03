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
			print("Sending {}...".format(hex2blocks(zero_pad+guess+known_values)))
			#Send this forgery to the server!
			response = connectme(forgery)
			if response == '':
				print("Warning: Empty response received. Possible timeout error.")
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

##The input text
# cookie = '5468697320697320616e2049563435366bfb3fae87ed7fa62690594a892409e6a4245eb2a5ff17ced3f0daf18f0cb05aaa9a2c4f43ade989de937a8439a7a9ea7f7ee59558d62d81db804a3b8ce1c5574dfdacead33f1fdf0580901129a2ec56'
cookie = '6bfb3fae87ed7fa62690594a892409e6a4245eb2a5ff17ced3f0daf18f0cb05aaa9a2c4f43ade989de937a8439a7a9ea7f7ee59558d62d81db804a3b8ce1c5574dfdacead33f1fdf0580901129a2ec56'
# cookie = '5468697320697320616e204956343536'
iv = [84, 104, 105, 115, 32, 105, 115, 32, 97, 110, 32, 73, 86, 52, 53, 54] #The ASCII value of 'This is an IV456' 
# iv = [200, 201, 179, 8, 12, 208, 195, 242, 230, 45, 237, 175, 203, 0, 105, 6]
# iv = [127, 126, 229, 149, 88, 214, 45, 129, 219, 128, 74, 59, 140, 225, 197, 87]
#iv = [169, 162, 196, 244, 58, 222, 152, 157, 233, 55, 168, 67, 154, 122, 158, 167]
#Assuming AES-128 (1 block = 16 bytes = 32 characters)
no_of_blocks = len(cookie)/32
plaintext =''
for block_no in range(no_of_blocks):
	#Initialize values...
	block_start = block_no * 32
	cipherblock = cookie[block_start:(block_start+32)]
	print(cipherblock)
	cipherblock_array = hex2blocks(cipherblock)
	print(cipherblock_array)
	decrypted_chain = decrypt_block(cipherblock)
	print("The intermediate value for block {} is: {}".format(block_no,decrypted_chain))
	plaintext_block = [decrypted_chain[i] ^ iv[i] for i in range(len(decrypted_chain))]
	# print(plaintext_block)
	#Before ASCII-fying the plaintext, check whether this is the last block. If this is the case, check for padding.
	if block_no == (no_of_blocks-1):
		pads_no = plaintext_block[-1]
		plaintext_block = plaintext_block[:len(plaintext_block)-pads_no]
	plaintext += asciify(plaintext_block)
	print("Current state of the plaintext is: {}".format(plaintext))
	#When done with decryption, change the previous_block to this block.
	iv = cipherblock_array
print(plaintext)
"""The intermediate value for block 4 is: [26, 92, 152, 152, 85, 219, 32, 140, 214, 141, 71, 54, 129, 236, 200, 90]
Current state of the plaintext is: {"username": "guest", "expires": "2000-01-07", "is_admin": "false"}
{"username": "guest", "expires": "2000-01-07", "is_admin": "false"}"""