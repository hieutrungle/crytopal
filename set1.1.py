# -*- coding: utf-8 -*-
"""
Created on Mon May 31 11:36:49 2021

@author: hieul
"""
import codecs

hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
b64 = codecs.encode(codecs.decode(hex, 'hex'), 'base64').decode()
print(b64)

# Manual code
b64_index_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def b64_encode(input_bytes):
    """Implements base64 encoding.
    """
    # Initialize variable that will store the base64 encoded string
    encoded_output = ''

    # Takes each input character and converts to binary, eventually creating
    # a list of ones and zeroes (1, 1, 1, 0, 0, 1, 1, 0)
    bit_list = list(''.join([bin(byte)[2:].zfill(8) for byte in input_bytes]))
    
    # Break the list smaller lists, 6 bits long. For example, [1,1,1,1,1,1,0,0]
    # becomes [[1,1,1,1,1,1] [0,0]]
    chunks = [bit_list[i:i+6] for i in range(0, len(bit_list), 6)]
    
    for chunk in chunks:
        # Joins the chunk so it can be converted to an integer
        chunk = ''.join(chunk)

        # Checks the length of the chunk, adding trailing zeroes, mapping the
        # value to the b64_index_table, and adding '=' characters as necessary.
        if len(chunk) == 2:
            if '1' in chunk:
                chunk += '0000'
                encoded_output += b64_index_table[int(chunk, 2)] + '=='
            else:
                encoded_output += '=='
        elif len(chunk) == 4: 
            if '1' in chunk:
                chunk += '00'
                encoded_output += b64_index_table[int(chunk, 2)] + '='
            else:
                encoded_output += '='
        elif len(chunk) == 6:
            encoded_output += b64_index_table[int(chunk, 2)]
    return encoded_output


def main():
    string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    byte_string = bytes.fromhex(string)
    print(b64_encode(byte_string))


if __name__ == '__main__':
    main()