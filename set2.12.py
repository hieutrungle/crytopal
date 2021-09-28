# -*- coding: utf-8 -*-
"""
Created on Wed Jun  2 12:16:23 2021

@author: hieul
"""

import random
from Crypto.Cipher import AES
import time
import base64

def gen_key():
    '''function to return key in byte type'''
    key = ''
    for i in range(AES.block_size):
        temp = chr(random.randint(0,100000) % 128)
        key += temp
    return key.encode(encoding='ascii')

random.seed(0)
key = gen_key() # global key
t = 1000 * time.time() # current time in milliseconds
random.seed(int(t) % 2**32)

def add_padding(buffer):
    if type(buffer) == str:
        buffer = str.encode(buffer)
    pad_len = AES.block_size
    quotient = len(buffer) // pad_len
    remainder = len(buffer) % pad_len
    if (remainder != 0):
        for i in range(len(buffer), pad_len*(quotient+1), 1):
            buffer += b'\x00'
    return buffer

def del_padding(buffer):
    if type(buffer) == str:
        buffer = str.encode(buffer)
    pad_len = AES.block_size
    padded = 0 # number of padding added
    for i in range(len(buffer) - 1, len(buffer) - pad_len - 1, -1):
        if (buffer[i] == buffer[-1]):
            padded += 1
        else:
            break
    buffer = buffer[:-padded]
    return buffer

def add_custome_pad(buffer, n_pad):
    if type(buffer) == str:
        buffer = str.encode(buffer)
    pad = b''
    for i in range(n_pad):
        pad += b'\x00'
    return pad + buffer + pad

def del_custome_pad(buffer, n_pad):
    if type(buffer) == str:
        buffer = str.encode(buffer)
    pad = b''
    for i in range(n_pad):
        pad += b'\x00'
    buffer = buffer[:-n_pad]
    buffer = buffer[n_pad:]
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
    key = str.encode(key)
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
    
    return plaintext

def encrypt_cbc(plaintext, key, iv):
    if type(plaintext) == str:
        plaintext = str.encode(plaintext)
    if (len(plaintext)%AES.block_size != 0):
        plaintext = add_padding(plaintext)
    ciphertext = b''
    prev_block = iv
    for i in range(0, len(plaintext), AES.block_size):
        ciphertext += encrypt_ecb_cipher(repeat_xor(plaintext[i:i+AES.block_size], prev_block), key)
        prev_block = ciphertext[i:i+AES.block_size]
    return ciphertext

def encrypt_oracle(plaintext):
    unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
            +"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
            +"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
            +"YnkK"
    unknown = str((base64.b64decode(unknown)))[2:]
    plaintext = add_padding(plaintext + unknown)
    return encrypt_ecb_cipher(plaintext, key)

def get_block_size(oracle):
    ciphertext_length = len(oracle(''))
    i = 1
    while True:
        data = ''
        data += ''.join(['A' for _ in range(i+1)])
        new_ciphertext_length = len(oracle(data))
        block_size = new_ciphertext_length - ciphertext_length
        if block_size:
            return block_size
        i += 1
        
def get_unknown_string_size(oracle):
    ciphertext_length = len(oracle(''))
    i = 0
    while True:
        data = ''
        data += ''.join(['A' for _ in range(i+1)])
        new_ciphertext_length = len(oracle(data))
        if ciphertext_length != new_ciphertext_length:
            return ciphertext_length - i
        i += 1

def count_aes_ecb_repetitions(ciphertext):
    """Counts the number of repeated chunks of the ciphertext and returns it."""
    chunks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    number_of_duplicates = len(chunks) - len(set(chunks))
    return number_of_duplicates

def is_ecb(ciphertext):
    return count_aes_ecb_repetitions(ciphertext)

def get_unknown_string(oracle):
    block_size = get_block_size(oracle)
    unknown_len = get_unknown_string_size(oracle)

    unknown_string = ''
    unknown_string_size_rounded = ((unknown_len // block_size) + 1) * block_size
    for i in range(unknown_string_size_rounded - 1, 0, -1):
        d1 = ''.join(['A' for _ in range(i)])
        c1 = oracle(d1)[:unknown_string_size_rounded]
        # print(f"len d1: {len(d1)}")
        for c in range(256):
            d2 = d1[:] + unknown_string + chr(c)
            c2 = oracle(d2)[:unknown_string_size_rounded]
            # print(f"len d2: {len(d2)}")
            if c1 == c2:
                unknown_string += chr(c)
                break
    return unknown_string

def main():
    # Feed string 'AAAAAAAAAAAAAAA' (15 char) to the oracle encyption, this 
    # will combine with the first letter of the unknown string (which is 'R').
    # Together they  produce encrypted block: b'\xed\x1f.^7,\\_)'
    # If feed 'AAAAAAAAAAAAAAAR' (16 char), it will produce the same encrypted
    # block b'\xed\x1f.^7,\\_)'. Therefore, the first letter is R
    # Repeatedly doing this will retrieve the unknown text.
    print(encrypt_oracle('AAAAAAAAAAAAAAA')[:16])
    print(encrypt_oracle('AAAAAAAAAAAAAAAR')[:16])
    
    ciphertext = (encrypt_oracle('YELLOW SUBMARINEYELLOW SUBMARINE'))
    print(f"\nIs this ecb encryption (0:No; >0: Yes)? \nAnswer: {is_ecb(ciphertext)}\n")
    
    unknown_len = get_unknown_string_size(encrypt_oracle)
    block_size = get_block_size(encrypt_oracle)
    print(f"unknown length: {unknown_len}")
    print(f"block size: {block_size}")
    unknown_ans = get_unknown_string(encrypt_oracle)
    print(f"\nUnknown string: \n{unknown_ans}")
    
    
if __name__ == "__main__":
    main()