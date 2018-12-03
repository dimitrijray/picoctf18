#!/usr/bin/python
from pwn import *
context.log_level = 'error'

def get_ciphertext(sitrep,PS):
	r = remote("2018shell.picoctf.com",37440)
	r.sendlineafter("Send & verify (S)\n",'e')
	r.sendlineafter("Please enter your situation report: ",sitrep)
	r.sendlineafter("Anything else? ",PS)
	ciphertext = r.recvuntil("Select",drop=True)
	ciphertext = ciphertext.replace('encrypted: ','')
	ciphertext = ciphertext.strip('\n')
	r.close()
	return ciphertext

def call_oracle(block):
	s = remote("2018shell.picoctf.com",37440)
	s.sendlineafter("Send & verify (S)\n",'s')
	s.sendlineafter("Please input the encrypted message: ",block)
	response = s.recvline(timeout=1.5)
	while response == '':
		print("Warning: empty response. Reconnecting...")
		response = s.recvline(timeout=1)
	s.close()
	return response

def lastbyte(b):
	return int(b[-2:],16)

def asciify(b):
	temp = [chr(c) for c in b]
	return "".join(temp)

#Begin guessing the flag.
flag = 'picoCTF{g0_@g3nt006!_297907'
unknown_characters = 20 #was established before. (was 17)
start_from = 0 #In case of failure, just start from this character. Otherwise just set to 0.
# unknown_characters = 1
# length_of_known_message = 138 #also precomputed
length_of_known_message = 142 #Was 138
flagblock = 8 #Where should we check for the ciphertext? (We begin from index 0)
xorblock = flagblock - 1 #The "previous block" for decryption
# r = remote("2018shell.picoctf.com",37440) #Open connection.
for guess in range(start_from,unknown_characters):
	print("Guessing character #{}.".format(guess+1))
	ones = 40 - guess #Precomputed, was 40 - guess
	sitrep = '00000000000' + '1'*ones #The "situation report"
	current_message_length = length_of_known_message + len(sitrep) + 20 #+length of sha-1 in hexa; Was 40.
	if current_message_length%16 == 0:
		PS = '' #The post-script is just an empty string.
	else:
		padding = 16 - (current_message_length % 16)
		PS = 'A'*padding #The post-script is such that the length of the message + the digest is divisible by 16.
	#Begin guessing.
	isGuessing = True
	trial = 1
	while (isGuessing):
		# if trial%10 == 0:
		print("Trial #{}...".format(trial))
		ciphertext = get_ciphertext(sitrep,PS)
		ciphertext_without_iv = ciphertext[32:]
		# print("Received ciphertext : {}".format(ciphertext_without_iv))
		#It is now ensured that the final block does not contain the MAC, and is therefore just a padding. Let us begin guessing...
		blockstart = 32*flagblock
		block_to_check = ciphertext_without_iv[blockstart:blockstart+32]
		truncated = ciphertext[:-32]
		block_to_send = truncated + block_to_check
		assert len(block_to_send) == len(ciphertext), "Invalid ciphertext length."
		response = call_oracle(block_to_send)
		if response.find("Ooops!") == -1:
			#The guess is correct! Get that last byte out.
			penultimate_last_byte = lastbyte(truncated)
			block_before_flag = lastbyte(ciphertext_without_iv[blockstart-2:blockstart])
			plaintext = (16 ^ penultimate_last_byte ^ block_before_flag)
			if (plaintext > 31 and plaintext < 127):
				flag = flag + chr(plaintext)
				print("Got it! It is: {}".format(chr(plaintext)))
			else:
				print("Warning: not an ASCII char.")
				flag = flag + '*'
			isGuessing = False
		if trial == 768: #Being a bit conservative.
			print("Warning: trial limit exceeded.")
			flag = flag + '*'
			break
		trial +=1
print(flag)
#picoCTF{g0_@g3nt006!_2979071}
#        0123456789012