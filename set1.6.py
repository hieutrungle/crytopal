# -*- coding: utf-8 -*-
"""
Created on Tue Jun  1 10:30:26 2021

@author: hieul
"""
import base64

def open_file(filename):
    '''Read file and convert to numpy array'''
    with open(filename) as input_file:
        ciphertext = base64.b64decode(input_file.read())
    return ciphertext

def compute_hamming_dist(byte1, byte2):
    xor_byte = [b1^b2 for b1, b2 in zip(byte1, byte2)]
    hamming_dist = 0
    for byte in xor_byte:
        hamming_dist += sum([1 for bit in bin(byte) if bit == '1'])
    return hamming_dist

def test_hamming_dist():
    string1 = "this is a test"
    string2 = "wokka wokka!!!"
    byte1 = str.encode(string1)
    byte2 = str.encode(string2)
    bin1 = [bin(byte) for byte in byte1]
    bin2 = [bin(byte) for byte in byte2]
    hamming_dist = compute_hamming_dist(string1, string2)
    print(hamming_dist)
    # result for hamming distance is 37

def compute_possible_key_len(cyphertext, low_key_len, high_key_len):
    average_distances = []
    for keysize in range(low_key_len, high_key_len):
        # Chunk of text for each keysize
        chunks = [cyphertext[i:i+keysize] for i in range(0, len(cyphertext), keysize)]
        # list to store all distance between 2 chunks
        distances = []
        
        # incremental element
        count = 0
        while True:
            # try:
            # Get hamming distance for 2 chunks at the beginning of the text
            chunk1 = chunks[count]
            chunk2 = chunks[count + 1]
            ham_dist = compute_hamming_dist(chunk1, chunk2)
            
            # Normalize distance and append to distances list
            distances.append(ham_dist/keysize)
            
            count += 2
            # except Exception as e:
            #     break
        
            if (count == len(chunks) or count+1 == len(chunks)):
                break
        # result stores key:value for each keysize
        result = {
            'keysize': keysize,
            'avg_distance': sum(distances)/len(distances)
            }
        average_distances.append(result)
    # Get the results having the smallest average distance
    possible_key_lengths = sorted(average_distances, key=lambda x: x['avg_distance'])[0]
    return possible_key_lengths["keysize"]

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
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_value])
    return output_bytes

def find_individual_key(ciphertext):
    """Performs a singlechar xor for each possible value(0,255), and
    assigns a score based on character frequency. Returns the result
    with the highest score.
    """
    potential_messages = []
    for key_value in range(256):
        message = single_char_xor(ciphertext, key_value)
        score = get_english_score(message)
        data = {
            'message': message,
            'score': score,
            'key': key_value
            }
        potential_messages.append(data)
    return sorted(potential_messages, key=lambda x: x['score'], reverse=True)[0]

def repeating_key_xor(message_bytes, key):
    ''''Repeatedly XOR'd with the found key'''
    output_bytes = b''
    count = 0
    for byte in message_bytes:
        output_bytes += bytes([byte ^ key[count%len(key)]])
        count += 1
    return output_bytes

def break_ciphertext(ciphertext, possible_key_len):
    '''Break the ciphertext after obtaining possible_key_len'''
    # keys list to store keys
    key = b''
    for index in range(possible_key_len):
        block = b''
        # Create each block associated with a specific index
        for j in range(index, len(ciphertext), possible_key_len):
            block += bytes([ciphertext[j]])
        # Find possible key for each block
        key += bytes([find_individual_key(block)['key']])
    # Repeatedly XOR with ASCII character to find the plain text
    plain_text = repeating_key_xor(ciphertext, key)
    return plain_text, key

def main():
    filename = "input_p6.txt"
    ciphertext = open_file(filename)
    possible_key_len = compute_possible_key_len(ciphertext, 2, 41)
    plain_text, key = break_ciphertext(ciphertext, possible_key_len)
    print(f"plain text: {plain_text}\nkey: {key}")
    
if __name__ == "__main__":
    main()