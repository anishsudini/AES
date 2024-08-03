# AES
AES Encryption &amp; Decryption (Supports Text Files)

The two commands below specify the exact command-line syntax for invoking encryption and decryption.

	1 python3 AES.py -e message.txt key.txt encrypted.txt
	2 python3 AES.py -d encrypted.txt key.txt decrypted.txt
 
• Encryption (indicated with the -e argument in line 1)

	– perform AES encryption on the plaintext in message.txt using the key in key.txt, and write the ciphertext to a file called encrypted.txt
	– You can assume that message.txt and key.txt contain textstrings (i.e. ASCII characters)
	– However, the final ciphertext should be saved as a single-line hexstring

• Decryption (indicated with the -d argument in line 2)

	– perform AES decryption on the ciphertext in encrypted.txt using the key in key.txt, and write the recovered plaintext to decrypted.txt
