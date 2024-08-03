# AES
AES Encryption &amp; Decryption (Supports Text Files)

The four commands below specify the exact command-line syntax for invoking encryption and decryption.

	1. python3 AES.py -e message.txt key.txt encrypted.txt
	2. python3 AES.py -d encrypted.txt key.txt decrypted.txt
 	3. python3 AES.py -i image.ppm key.txt enc_image.ppm
  	4. python3 AES.py -r 3 key.txt random_numbers.txt
 
- Encryption (indicated with the -e argument in line 1)
⋅⋅⋅perform AES encryption on the plaintext in message.txt using the key in key.txt, and write the ciphertext to a file called encrypted.txt

– You can assume that message.txt and key.txt contain textstrings (i.e. ASCII characters)

– However, the final ciphertext should be saved as a single-line hexstring

• Decryption (indicated with the -d argument in line 2) –

– perform AES decryption on the ciphertext in encrypted.txt using the key in key.txt, and write the recovered plaintext to decrypted.txt

• Image Counter-Mode AES Encryption (indicated with the -i argument in line 3) –

 – perform AES counter-mode encryption on a .ppm image file using the key in key.txt, and writes the encrypted image file to enc_image.ppm

• X9.31 CSPRNG (crytographically secure pseudo-random number generator) (indicated with the -r argument in line 4) –

– This method uses the arguments with the X9.31 algorithm to compute totalNum number of pseudo-random numbers, each represented as BitVector objects.

– These numbers are then written to the output file in base 10 notation.

– Currently the initial vector and date time are intiailized and set to "counter-mode-ctr" and 501 respectively but can be updated to be anything.
