# Python version 3.9 or later
import re
import math
from collections import Counter


# Create a dict for letter frequency analysis.
letter_frequency = {
    'e': 12.7, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75,
    's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
    'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97,
    'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07
}

# Create a helper method to calculate score for outcoming
def get_score(plaintext):
    if isinstance(plaintext, bytes):
        plaintext = plaintext.decode(errors='ignore')
    text = re.sub(r'[^a-z]', '', plaintext)
    text = text.lower()
    letter_counts = Counter(text)
    # print(letter_counts)
    chars = sum(letter_counts.values())

    score = 0

    for letter, expected_freq in letter_frequency.items():
        real_freq = (letter_counts.get(letter, 0) / chars) * 100 if chars else 0
        score += abs(real_freq - expected_freq)

    return score

# Complete the functions below and include this file in your submission.
#
# You can verify your solution by running `problem_2.py`. See `problem_2.py` for more
# details.

# ------------------------------------- IMPORTANT --------------------------------------
# Do NOT modify the name or signature of the three functions below. You can, however,
# add any additional functons to this file.
# --------------------------------------------------------------------------------------

# Given a ciphertext enciphered using the Caesar cipher, recover the plaintext.
# In the Caesar cipher, each byte of the plaintext is XORed by the key (which is a
# single byte) to compute the ciphertext.
#
# The input `ciphertext` is a bytestring i.e., it is an instance of `bytes`
# (see https://docs.python.org/3.9/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview).
# The function should return the plaintext, which is also a bytestring.
def break_caesar_cipher(ciphertext):
    best_score = math.inf
    plaintext_result = b''

    for k in range(256):
        plaintext_k = bytes([byte ^ k for byte in ciphertext])
        try:
            score_k = get_score(plaintext_k.decode(errors='ignore'))
            if score_k < best_score:
                best_score = score_k
                plaintext_result = plaintext_k
        except UnicodeDecodeError:
            continue

    return plaintext_result


# Given a ciphertext enciphered using a Vigenere cipher, find the length of the secret
# key using the 'index of coincidence' method.
#
# The input `ciphertext` is a bytestring.
# The function returns the key length, which is an `int`.
def find_vigenere_key_length(ciphertext):
    key_length_result = 0
    best_ic = 0

    def index_of_coincidence(input_text):
        text_len = len(input_text)
        if len(input_text) < 2: return 0
        char_frequency = Counter(input_text)
        ic_sum = 0
        for char, f in char_frequency.items():
            ic_sum = ic_sum + f * (f - 1)
        ic = ic_sum / (text_len * (text_len - 1))
        return ic

    for k in range(1, 20 + 1):
        ic_values = []
        for i in range(k):
            subset = ciphertext[i::k]
            ic_values.append((index_of_coincidence(subset)))

        avg_ic = sum(ic_values) / len(ic_values)

        if avg_ic > best_ic:
            best_ic = avg_ic
            key_length_result = k

    return key_length_result


# Given a ciphertext enciphered using a Vigenere cipher and the length of the key,
# recover the plaintext.
#
# The input `ciphertext` is a bytestring.
# The function should return the plaintext, which is also a bytestring.
def break_vigenere_cipher(ciphertext, key_length):

    cipher_groups = [ciphertext[i::key_length] for i in range(key_length)]

    key = []
    for group in cipher_groups:
        best_k = None
        best_score = math.inf

        for k in range(256):
            decrypted_attempt = bytes([byte ^ k for byte in group])
            try:
                score = get_score(decrypted_attempt)
                if score < best_score:
                    best_score = score
                    best_k = k
            except UnicodeDecodeError:
                continue
        key.append(best_k)

    key_str = ''.join(map(chr, key))

    key_pad = ""
    while len(key_pad) < len(ciphertext):
        key_pad += key_str
    key_pad = key_pad[:len(ciphertext)]

    plaintext_byte = []
    for i in range(len(ciphertext)):
        byte_decrypted = ciphertext[i] ^ ord(key_pad[i])
        plaintext_byte.append(byte_decrypted)

    plaintext = bytes(plaintext_byte)
    return plaintext

