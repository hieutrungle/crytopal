# -*- coding: utf-8 -*-
"""
Created on Tue Jun  1 10:03:12 2021

@author: hieul
"""

def get_english_score(input_bytes):
    """Compares each input byte to a character frequency 
    chart and returns the score of a message based on the
    relative frequency the characters occur in the English
    language
    """

    # From https://en.wikipedia.org/wiki/Letter_frequency
    # with the exception of ' ', which I estimated.
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])


def single_char_xor(input_bytes, char_value):
    """Returns the result of each byte being XOR'd with a single value.
    """
    output_bytes = b''
    count = 0
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_value[count%3]])
        count += 1
    return output_bytes


def main():
    my_str = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ciphertext = str.encode(my_str)
    print(ciphertext)
    key_value = [73, 67, 69] # ICE key word
    message = single_char_xor(ciphertext, key_value)
    print(type(message))
    message = message.hex()
    print(type(message))
    print(message)
    
    true_ans = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    print(true_ans)
    print(type(true_ans))
    if (message == true_ans):
        print("Correct")
    
if __name__ == '__main__':
    main()