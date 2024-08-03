import sys
from BitVector import *
import time

class AES ():
# class constructor - when creating an AES object, the
# class’s constructor is executed and instance variables
# are initialized
    def __init__(self, keyfile:str) -> None:
        self.AES_modulus = BitVector(bitstring='100011011')
        self.subBytesTable = []                              # for encryption
        self.invSubBytesTable = []                           # for decryption

        self.genTables()

        key_file = open(keyfile, 'r')
        key = key_file.read()
        key_file.close()

        key_words = []
        key = key.strip()
        key += '0' * (32 - len(key)) if len(key) < 32 else key[:32]  
       
        key_bv = BitVector(textstring = key)
        key_words = self.gen_key_schedule_256(key_bv)

        key_schedule = []
       
        for word_index,word in enumerate(key_words):
            keyword_in_ints = []
            for i in range(4):
                if word_index % 4 == 0: 
                    print("\n")
            key_schedule.append(keyword_in_ints)
        
        num_rounds = 14
        self.round_keys = [None for i in range(num_rounds+1)]
        for i in range(num_rounds+1):
            self.round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]).get_bitvector_in_hex()

        return
    
    def genTables(self): 
        c = BitVector(bitstring='01100011')
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
            # For the encryption SBox
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            # For bit scrambling for the encryption SBox entries:
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            self.subBytesTable.append(int(a))
            # For the decryption Sbox:
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            self.invSubBytesTable.append(int(b))

    def gen_key_schedule_256(self, key_bv): 
        byte_sub_table = self.gen_subbytes_table()
        #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
        #  schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words
    
    def gen_subbytes_table(self): 
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable
    
    def gee(self, keyword, round_constant, byte_sub_table): 
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant

    def state_array(self, bitvec_Hex):
        
        new_bitvec_Hex = []
        for i in range(0, len(bitvec_Hex), 2):
            new_bitvec_Hex.append([bitvec_Hex[i:i + 2]])

        statearray = [[0 for x in range(4)] for x in range(4)]
        k = 0
        for i in range(4):
            for j in range(4):
                statearray[j][i] = new_bitvec_Hex[k][0]
                k += 1
        
        return statearray

    def sub_bytes(self, statearray):
        for i in range(4):
            for j in range(4):
                statearray[j][i] = BitVector(intVal=self.subBytesTable[int(statearray[j][i], 16)], size=8).get_bitvector_in_hex()

        return statearray
    
    def shift_rows(self, statearray): 
        shift = [1, 2, 3]
        for i in shift:
            statearray[i] = statearray[i][i:] + statearray[i][:i]

        return statearray

    def mix_columns(self, statearray): 
        mix = [[2, 3, 1, 1],
               [1, 2, 3, 1],
               [1, 1, 2, 3],
               [3, 1, 1, 2]]
        product = [['', '', '', ''],
                   ['', '', '', ''],
                   ['', '', '', ''],
                   ['', '', '', '']]
        
        for i in range(4):
            for j in range(4):
                bv = BitVector(intVal = 0, size = 8)
                for k in range(4):
                    mix_bv = BitVector(intVal=mix[i][k])
                    temp = mix_bv.gf_multiply_modular(BitVector(intVal=int(statearray[k][j], 16)), self.AES_modulus, 8)
                    if(temp.length() < 8):
                        temp.pad_from_left(8 - temp.length())
                    bv ^= temp
                product[i][j] += bv.get_bitvector_in_hex()
        return product    

    # encrypt - method performs AES encryption on the plaintext and writes the ciphertext to disk
    # Inputs: plaintext (str) - filename containing plaintext
    # ciphertext (str) - filename containing ciphertext
    # Return: void
    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        bv = BitVector(filename = plaintext)
        encrypted_file = open(ciphertext, "w")

        while(bv.more_to_read):
            bitvec = bv.read_bits_from_file(128)
            
            if(bitvec.length() < 128):
                bitvec.pad_from_right(128 - bitvec.length())

            #Step 1: Add Round Key
            bitvec_hex_string = bitvec.get_bitvector_in_hex()
            bitvec_Hex = BitVector(hexstring=bitvec_hex_string) ^ BitVector(hexstring=self.round_keys[0])
            bitvec_Hex = bitvec_Hex.get_bitvector_in_hex()

            #Step 2: Rounds 1 - 14
            num_rounds = 1
            while(num_rounds < 14):
                #Step 2-a: BitVector -> State Array of Bytes (as elements)
                statearray = self.state_array(bitvec_Hex) 

                #Step 2-b: Round Step 1: Substitute Bytes
                statearray = self.sub_bytes(statearray) 

                #Step 2-c: Round Step 2: Shift Rows
                statearray = self.shift_rows(statearray) 
                
                #Step 2-d: Round Step 3: Mix Columns
                statearray = self.mix_columns(statearray) 

                #Step 2-e: Round Step 4: Add/XOR Round Key
                statearray_string = ""
                for i in range(4):
                    for j in range(4):
                        statearray_string += statearray[j][i]
                bitvec_Hex = (BitVector(hexstring=statearray_string) ^ BitVector(hexstring=self.round_keys[num_rounds])).get_bitvector_in_hex()
                num_rounds += 1

            if num_rounds == 14:
                statearray = self.state_array(bitvec_Hex)
                
                statearray = self.sub_bytes(statearray)
                
                statearray = self.shift_rows(statearray)
                
                statearray_string = ""
                for i in range(4):
                    for j in range(4):
                        statearray_string += statearray[j][i]
                bitvec_Hex = (BitVector(hexstring=statearray_string) ^ BitVector(hexstring = self.round_keys[num_rounds])).get_bitvector_in_hex()
                encrypted_file.write(bitvec_Hex)

        encrypted_file.close()

        return 
    
    def inverse_shift_rows(self, statearray): 
        shift = [1, 2, 3]
        for i in shift:
            statearray[i] = statearray[i][-i:] + statearray[i][:-i]

        return statearray
    
    def inverse_sub_bytes(self, statearray): 
        for i in range(4):
            for j in range(4):
                statearray[j][i] = BitVector(intVal=self.invSubBytesTable[int(statearray[j][i], 16)], size=8).get_bitvector_in_hex()

        return statearray
    
    def inverse_mix_columns(self, statearray): 
        mix = [['0e', '0b', '0d', '09'],
               ['09', '0e', '0b', '0d'],
               ['0d', '09', '0e', '0b'],
               ['0b', '0d', '09', '0e']]
        product = [['', '', '', ''],
                   ['', '', '', ''],
                   ['', '', '', ''],
                   ['', '', '', '']]
        
        for i in range(4):
            for j in range(4):
                bv = BitVector(intVal = 0, size = 8)
                for k in range(4):
                    mix_bv = BitVector(intVal=int(mix[i][k], 16))
                    temp = mix_bv.gf_multiply_modular(BitVector(intVal=int(statearray[k][j], 16)), self.AES_modulus, 8)
                    if(temp.length() < 8):
                        temp.pad_from_left(8 - temp.length())
                    bv ^= temp
                product[i][j] += bv.get_bitvector_in_hex()

        return product
    
    # decrypt - method performs AES decryption on the ciphertext and writes the recovered plaintext to disk
    # Inputs: ciphertext (str) - filename containing ciphertext
    # decrypted (str) - filename containing recovered plaintext
    # Return: void
    def decrypt(self, ciphertext:str, decrypted:str) -> None:
        with open(ciphertext, 'r') as file:
            hex_string = file.read().strip()

        binary_string = ''.join(format(int(hex_char, 16), '04b') for hex_char in hex_string)

        decrypted_file = open(decrypted, "w")

        index = 0
        while index < len(binary_string):
            # Extract 128 bits (16 bytes) from the binary string
            bitvec = BitVector(bitstring=binary_string[index:index+128])
            index += 128

            #Step 1: Add Last Round Key
            bitvec_Hex = (bitvec ^ BitVector(hexstring=self.round_keys[14])).get_bitvector_in_hex()

            #Step 2: Rounds 1 - 14
            num_rounds = 13
            while(num_rounds > 0):
                #Step 2-a: BitVector -> State Array of Bytes (as elements)
                statearray = self.state_array(bitvec_Hex) #statearray elements are Hex Strings
                
                #Step 2-b: Round Step 1: Inverse Shift Rows
                statearray = self.inverse_shift_rows(statearray)
                
                #Step 2-c: Round Step 2: Inverse Substitute Bytes
                statearray = self.inverse_sub_bytes(statearray)
                
                #Step 2-d: Round Step 3: Add Round Key
                statearray_string = ""
                for i in range(4):
                    for j in range(4):
                        statearray_string += statearray[j][i]
                bitvec_Hex = (BitVector(hexstring=statearray_string) ^ BitVector(hexstring=self.round_keys[num_rounds])).get_bitvector_in_hex()
                statearray = self.state_array(bitvec_Hex)
                
                #Step 2-e: Round Step 4: Inverse Mix Columns
                statearray = self.inverse_mix_columns(statearray)
                statearray_t = list(zip(*statearray))
                new_hex_string = ''.join(''.join(column) for column in statearray_t)
                bitvec_Hex = BitVector(hexstring=new_hex_string).get_bitvector_in_hex()
                num_rounds -= 1
            
            if num_rounds == 0:
                statearray = self.state_array(bitvec_Hex) 

                statearray = self.inverse_shift_rows(statearray)

                statearray = self.inverse_sub_bytes(statearray)

                statearray_string = ""
                for i in range(4):
                    for j in range(4):
                        statearray_string += statearray[j][i]
                bitvec_Hex = (BitVector(hexstring=statearray_string) ^ BitVector(hexstring=self.round_keys[num_rounds])).get_text_from_bitvector()
                decrypted_file.write(bitvec_Hex)

        decrypted_file.close()

        return 

    def ctr_aes_encrypt(self, iv, bv, file) -> None:
        increment = 1

        while(bv.more_to_read):
            bitvec = bv.read_bits_from_file(128)
            
            if(bitvec.length() < 128):
                bitvec.pad_from_right(128 - bitvec.length())
            
            if(iv.length() < 128):
                iv.pad_from_left(128 - iv.length())

            iv_hex_string = iv.get_bitvector_in_hex()
            bitvec_Hex = BitVector(hexstring=iv_hex_string) ^ BitVector(hexstring=self.round_keys[0])
            bitvec_Hex = bitvec_Hex.get_bitvector_in_hex()

            #Step 2: Rounds 1 - 14
            num_rounds = 1
            while(num_rounds < 14):
                #Step 2-a: BitVector -> State Array of Bytes (as elements)
                statearray = self.state_array(bitvec_Hex) 

                #Step 2-b: Round Step 1: Substitute Bytes
                statearray = self.sub_bytes(statearray) 

                #Step 2-c: Round Step 2: Shift Rows
                statearray = self.shift_rows(statearray) 
                
                #Step 2-d: Round Step 3: Mix Columns
                statearray = self.mix_columns(statearray) 

                #Step 2-e: Round Step 4: Add/XOR Round Key
                statearray_string = ''.join([statearray[j][i] for i in range(4) for j in range(4)])
                bitvec_Hex = (BitVector(hexstring=statearray_string) ^ BitVector(hexstring=self.round_keys[num_rounds])).get_bitvector_in_hex()
                num_rounds += 1

            if num_rounds == 14:
                statearray = self.state_array(bitvec_Hex)
                
                statearray = self.sub_bytes(statearray)
                
                statearray = self.shift_rows(statearray)
                
                statearray_string = ''.join([statearray[j][i] for i in range(4) for j in range(4)])
                bitvec_Hex = (BitVector(hexstring=statearray_string) ^ BitVector(hexstring = self.round_keys[num_rounds]))
                
                output = bitvec_Hex ^ bitvec
                output.write_to_file(file)
                iv = BitVector(intVal=(iv.int_val() + int((increment % (2**128)))))
                increment += 1
        return

    def ctr_aes_image(self, iv, image_file, enc_image) -> None:
        image = open(image_file, 'rb')
        header_line1 = image.readline()
        header_line2 = image.readline()
        header_line3 = image.readline()

        encrypted_image_file = open(enc_image, "wb")
        encrypted_image_file.write(header_line1)
        encrypted_image_file.write(header_line2)
        encrypted_image_file.write(header_line3)

        bv = BitVector(filename = image_file)
        image.close()

        self.ctr_aes_encrypt(iv, bv, encrypted_image_file)

        encrypted_image_file.close()       
        return
    
    def x931_AES_encrypt(self, bv):
        #Step 1: Add Round Key
        bv_hex_string = bv.get_bitvector_in_hex()
        bv_Hex = (BitVector(hexstring=bv_hex_string) ^ BitVector(hexstring=self.round_keys[0]))
        bv_Hex = bv_Hex.get_bitvector_in_hex()

        #Step 2: Rounds 1 - 14
        num_rounds = 1
        while(num_rounds < 14):
            #Step 2-a: BitVector -> State Array of Bytes (as elements)
            statearray = self.state_array(bv_Hex) 

            #Step 2-b: Round Step 1: Substitute Bytes
            statearray = self.sub_bytes(statearray) 

            #Step 2-c: Round Step 2: Shift Rows
            statearray = self.shift_rows(statearray) 
            
            #Step 2-d: Round Step 3: Mix Columns
            statearray = self.mix_columns(statearray) 

            #Step 2-e: Round Step 4: Add/XOR Round Key
            statearray_string = ''.join([statearray[j][i] for i in range(4) for j in range(4)])
            bv_Hex = (BitVector(hexstring=statearray_string) ^ BitVector(hexstring=self.round_keys[num_rounds])).get_bitvector_in_hex()
            num_rounds += 1

        if num_rounds == 14:
            statearray = self.state_array(bv_Hex)
            
            statearray = self.sub_bytes(statearray)
            
            statearray = self.shift_rows(statearray)
            
            statearray_string = ''.join([statearray[j][i] for i in range(4) for j in range(4)])
            enc_bv = (BitVector(hexstring=statearray_string) ^ BitVector(hexstring = self.round_keys[num_rounds]))
        
        return enc_bv

    def x931(self, v0, dt, totalNum, outfile) -> None:
        """
        Inputs:
            v0 (BitVector): 128 -bit seed value
            dt (BitVector): 128 -bit date/time value
            totalNum (int): total number of pseudo -random numbers to generate

        Method Description:
        * This method uses the arguments with the X9.31 algorithm to compute totalNum number of pseudo-random numbers, 
        each represented as BitVector objects.
        * These numbers are then written to the output file in base 10 notation.
        * Method returns void
        """
        enc_dt = self.x931_AES_encrypt(dt)
        output = open(outfile, "w")

        while(totalNum > 0):
            v_xor_dt = v0 ^ enc_dt
            r = self.x931_AES_encrypt(v_xor_dt)
            output.write(str(int(r))+"\n")
            r_xor_dt = r ^ enc_dt
            v0 = self.x931_AES_encrypt(r_xor_dt)
            totalNum -= 1
    
        output.close()
        return

if __name__ == "__main__":
    cipher = AES(keyfile = sys.argv[3])

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext = sys.argv[2], ciphertext = sys.argv[4])

    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext = sys.argv[2], decrypted = sys.argv[4])

    elif sys.argv[1] == "-i":
        start = time.time() 
        cipher.ctr_aes_image(iv = BitVector(textstring="counter-mode-ctr"), image_file = sys.argv[2], enc_image = sys.argv[4])
        end = time.time()
        print(end - start) 
    
    elif sys.argv[1] == "-r": 
        cipher.x931(v0 = BitVector(textstring="counter-mode-ctr"), dt = BitVector(intVal=501, size=128), totalNum = int(sys.argv[2]), outfile = sys.argv[4])

    else: 
        sys.exit("Incorrect Command - Line Syntax")
