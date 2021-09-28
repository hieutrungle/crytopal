
# -*- coding: utf-8 -*-
"""
Created on Wed Jun  2 09:53:16 2021

@author: hieul
"""

import random
from Crypto.Cipher import AES

# random.seed(0)

def gen_key():
    '''function to return key in byte type'''
    key = b''
    for i in range(AES.block_size):
        temp = chr((random.randint(0,100000) % 126) + 1)
        key += str.encode(temp)
    return key

def add_padding(buffer):
    pad_len = AES.block_size
    quotient = len(buffer) // pad_len
    remainder = len(buffer) % pad_len
    if (remainder != 0):
        for i in range(len(buffer), pad_len*(quotient+1), 1):
            buffer += b'\x00'
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
        print("a")
    if (len(plaintext)%AES.block_size != 0):
        plaintext = add_padding(plaintext)
    ciphertext = b''
    prev_block = iv
    for i in range(0, len(plaintext), AES.block_size):
        ciphertext += encrypt_ecb_cipher(repeat_xor(plaintext[i:i+AES.block_size], prev_block), key)
        prev_block = ciphertext[i:i+AES.block_size]
    return ciphertext

    
def test_cbc(plaintext):
    plaintext = str.encode(plaintext)
    n_pad = random.randint(5,10)
    plaintext = add_custome_pad(plaintext, n_pad)
    print(f"\nplaintext: \n{plaintext}")
    key = gen_key()
    iv = b'\x00'
    iv = add_padding(iv)
    ciphertext = encrypt_cbc(plaintext, key, iv)
    print(f"\nciphertext: \n{ciphertext}")
    plaintext = decrypt_cbc(ciphertext, key, iv)
    plaintext = del_custome_pad(plaintext, n_pad)
    plaintext = del_padding(plaintext)
    print(f"\nplaintext: \n{plaintext}")

def custom_encrypt(plaintext):
    ''' Encrypt first half of the message using either cbc or ecb,
        the second half will be encrypted with the other algorithm
    '''
    if type(plaintext) == str:
        plaintext = str.encode(plaintext)
    is_ecb_first = False
    
    # Add padding before and after the plaintext
    n_pad = random.randint(5,10)
    plaintext = add_custome_pad(plaintext, n_pad)
    
    # Generate pseudo-random key
    key = gen_key()
    iv = b'\x00'
    iv = add_padding(iv)
    
    
    # Split into 2 halves to encrypt
    # Add padding before encryption
    first_half = plaintext[:int(len(plaintext)/2)]
    second_half = plaintext[int(len(plaintext)/2):]
    first_half = add_padding(first_half)
    second_half = add_padding(second_half)
    
    # Encryption
    encrypt_mess = b''
    if (random.randint(0,1) == 0):
        is_ecb_first = True
        encrypt_mess += encrypt_ecb_cipher(first_half, key)
        encrypt_mess += encrypt_cbc(second_half, key, iv)
    else:
        encrypt_mess += encrypt_cbc(first_half, key, iv)
        encrypt_mess += encrypt_ecb_cipher(second_half, key)
    print(f"\nencrypt_mes: \n{encrypt_mess}")
    
    # Decryption
    decrypt_mess = b''
    len_first_half = len(first_half)
    if (is_ecb_first == True):
        decrypt_mess += decrypt_ecb_cipher(encrypt_mess[:len_first_half], key)
        decrypt_mess = del_padding(decrypt_mess)
        decrypt_mess += decrypt_cbc(encrypt_mess[len_first_half:], key, iv)
    else:
        decrypt_mess += decrypt_cbc(encrypt_mess[:len_first_half], key, iv)
        decrypt_mess = del_padding(decrypt_mess)
        decrypt_mess += decrypt_ecb_cipher(encrypt_mess[len_first_half:], key)
    # Remove padding
    decrypt_mess = del_custome_pad(decrypt_mess, n_pad)
    decrypt_mess = del_padding(decrypt_mess)
    print(f"\ndecrypt_mess: \n{decrypt_mess}")

def main():
    my_text = "Now that you have ECB and CBC working:" \
            + " Write a function to generate a random AES key; that's just 16 random bytes." \
            + " Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it." \
            + " The function should look like:"
    custom_encrypt(my_text)
    
if __name__ == "__main__":
    main()