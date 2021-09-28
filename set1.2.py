# -*- coding: utf-8 -*-
"""
Created on Mon May 31 11:51:15 2021

@author: hieul
"""

# Manually convert hex to binary
def byte_to_bin(input_bytes):
    # Takes each input character and converts to binary, eventually creating
    # a list of ones and zeroes (1, 1, 1, 0, 0, 1, 1, 0)
    bin_string = ''.join([bin(byte)[2:].zfill(8) for byte in input_bytes])
    return bin_string

def hex_to_bin(hex_string):
    byte_string = bytes.fromhex(hex_string)
    bin_string = byte_to_bin(byte_string)
    return bin_string
    
def main():
    string ="1c0111001f010100061a024b53535009181c"
    string_to_xor = "686974207468652062756c6c277320657965"
    
    # Using manually created function to convert hex to binary
    bin_string = hex_to_bin(string)
    bin_string_to_xor = hex_to_bin(string_to_xor)
    
    # Second approach to convert hex to binary
    scale = 16 ## equals to hexadecimal
    num_of_bits = 8
    bin_string = bin(int(string, scale))[2:].zfill(num_of_bits)
    bin_string = bin(int(string, scale))
    bin_string_1 = bin(int(string_to_xor, scale))

    # 1st method to xor from 2 binary
    result_xor = hex(int(bin_string,2)^ int(bin_string_to_xor,2))
    print(result_xor)

    # 2nd method to xor from 2 hex
    result_xor = hex(int(string,16)^ int(string_to_xor,16))
    print(result_xor)
    
if __name__ == "__main__":
    main()