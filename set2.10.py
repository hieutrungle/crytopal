# -*- coding: utf-8 -*-
"""
Created on Tue Jun  1 21:47:23 2021

@author: hieul
"""

import base64
from Crypto.Cipher import AES

def open_fileb64(filename):
    '''Read file and convert to numpy array'''
    with open(filename) as input_file:
        ciphertext = base64.b64decode(input_file.read())
    return ciphertext

def add_padding(buffer):
    pad_len = 16
    quotient = len(buffer) // pad_len
    remainder = len(buffer) % pad_len
    if (remainder != 0):
        for i in range(len(buffer), pad_len*(quotient+1), 1):
            buffer += b"\x00"
    return buffer

def del_padding(buffer):
    pad_len = 16
    padded = 0 # number of padding added
    for i in range(len(buffer) - 1, len(buffer) - pad_len - 1, -1):
        if (buffer[i] == buffer[-1]):
            padded += 1
        else:
            break
    buffer = buffer[:-padded]
    return buffer

def decrypt_ecb_cipher(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def encrypt_ecb_cipher(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def repeat_xor(message_bytes, key):
    ''''Repeatedly XOR'd with the found key'''
    output_bytes = b''
    count = 0
    for byte in message_bytes:
        output_bytes += bytes([byte ^ key[count%len(key)]])
        count += 1
    return output_bytes

def decrypt_cbc(ciphertext, key, iv):
    plaintext = b''
    prev_block = iv
    for i in range(0, len(ciphertext), AES.block_size):
        plaintext += \
            repeat_xor(decrypt_ecb_cipher(ciphertext[i:i+AES.block_size], key), prev_block)
        prev_block = ciphertext[i:i+AES.block_size]
    plaintext = del_padding(plaintext)
    return plaintext

def main():
    filename = "input_p10.txt"
    ciphertext = open_fileb64(filename)
    ciphertext = add_padding(ciphertext)
    
    key = b'YELLOW SUBMARINE'
    iv = b"\x00"
    iv = add_padding(iv)
    
    plaintext = decrypt_cbc(ciphertext, key, iv)
    print(plaintext)
    
if __name__ == '__main__':
    main()