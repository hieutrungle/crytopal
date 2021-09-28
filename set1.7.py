# -*- coding: utf-8 -*-
"""
Created on Tue Jun  1 15:57:17 2021

@author: hieul
"""
import base64
from Crypto.Cipher import AES

def open_fileb64(filename):
    '''Read file and convert to numpy array'''
    with open(filename) as input_file:
        ciphertext = base64.b64decode(input_file.read())
    return ciphertext

def decrypt_ecb_cipher(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def main():
    filename = "input_p7.txt"
    ciphertext = open_fileb64(filename)
    print(len(ciphertext))
    
    key = b'YELLOW SUBMARINE'
    message = decrypt_ecb_cipher(ciphertext, key)
    print(message)
    
    
if __name__ == '__main__':
    main()