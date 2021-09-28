# -*- coding: utf-8 -*-
"""
Created on Tue Jun  1 19:40:17 2021

@author: hieul
"""

def add_padding(ciphertext):
    pad_len = 20
    for i in range(len(ciphertext), pad_len, 1):
        ciphertext += b"\x04"
    return ciphertext

def main():
    my_str = "YELLOW SUBMARINE"
    ciphertext = str.encode(my_str)
    print(ciphertext)
    ciphertext = add_padding(ciphertext)
    print(ciphertext)
    
if __name__ == "__main__":
    main()