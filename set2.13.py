# -*- coding: utf-8 -*-
"""
Created on Wed Jun  2 17:30:26 2021

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

def add_padding(buffer, block_size):
    if type(buffer) == str:
        buffer = str.encode(buffer)
    pad_len = block_size
    quotient = len(buffer) // pad_len
    remainder = len(buffer) % pad_len
    if (remainder != 0):
        for i in range(len(buffer), pad_len*(quotient+1), 1):
            buffer += b'\x00'
    return buffer

def del_padding(buffer, block_size):
    if type(buffer) == str:
        buffer = str.encode(buffer)
    pad_len = block_size
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

def encrypt_oracle(plaintext):
    unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
            +"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
            +"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
            +"YnkK"
    unknown = str((base64.b64decode(unknown)))[2:]
    plaintext = add_padding(plaintext + unknown, AES.block_size)
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

def parsing(text):
    '''input format: foo=bar&baz=qux&zap=zazzle'''
    kv_list = text.strip().split('&')
    out_dict = {}
    for i in range(len(kv_list)):
        kv = kv_list[i].strip().split('=')
        out_dict[kv[0]] = kv[1]
    return out_dict
    
def profile_for(text):
    '''input format: foo@bar.com'''
    for char in text:
        if (char == '&' or char == '='):
            print("Remove character: '&'; '='")
            exit
    out_string = "email="+text+"&uid=10&role=user"
    parsing(out_string)
    return encrypt_oracle(out_string)

def deprofile_for(ciphertext):
    return decrypt_ecb_cipher(ciphertext, key)

def create_admin_profile():
    block_size = get_block_size(profile_for)
    
    # Fixed byte of profile
    fixed_byte = "email=&uid=10&role="
    full_encode_len = (len(fixed_byte)//block_size + 1) * block_size
    email_len = full_encode_len - len(fixed_byte)
    email = 'A' * email_len
    profile_prefix = profile_for(email)[:full_encode_len]
    # print(deprofile_for(profile_prefix))
    
    fixed_byte1 = "email="
    full_encode_len1 = (len(fixed_byte1)//block_size + 1) * block_size
    email_len1 = full_encode_len1 - len(fixed_byte1)
    email1 = 'A' * email_len1
    email1 += str(add_padding("admin", block_size))[2:]
    print("print encode string:")
    print(str(add_padding("admin", block_size)))
    print(email1)
    profile_postfix = profile_for(email1)[full_encode_len1:full_encode_len1+block_size]
    print()
    print(deprofile_for(profile_postfix))
    profile = profile_prefix + profile_postfix
    
    return del_padding(deprofile_for(profile), AES.block_size)

def main():
    my_txt = "foo=bar&baz=qux&zap=zazzle"
    parsing(my_txt)
    encoded_string = profile_for("hieult1996@gmail.com")
    # print(encoded_string)
    admin_profile = create_admin_profile()
    print(admin_profile)
    
if __name__ == '__main__':
    main()