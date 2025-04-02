
AES_BLOCK_SIZE = 16

"""
Solution to Assignment 2

Python version 3.9 or later.

Your final submission must contain the following functions:
    - solve_padding_oracle(ctx, server)
    - find_cookie_length(server)
    - find_cookie(server)
"""


def solve_padding_oracle(ctx, server):
    """
    Recovers the original plaintext message from a given ciphertext using a padding oracle attack.

    Parameters:
        ctx (bytes): A ciphertext produced using AES in CBC mode. The first AES_BLOCK_SIZE bytes
                     of ctx are the Initialization Vector (IV), and the remaining bytes are the ciphertext.

        server (function): A padding oracle function with the signature:
                               server(ciphertext: bytes) -> bool
                           When passed a ciphertext, the server function decrypts it (using the unknown key)
                           and returns True if the resulting plaintext has valid PKCS#7 padding,
                           or False if the padding is invalid.

    Returns:
        bytes: The recovered plaintext message with the padding removed.
    """
    # P1 - Extract iv, cipher -> divide them into blocks.
    iv = ctx[:AES_BLOCK_SIZE]       # get iv [0:16]
    cipher = ctx[AES_BLOCK_SIZE:]   # get ctx [16:]
    blocks = [iv] + [cipher[i:i + AES_BLOCK_SIZE] for i in range(0, len(cipher), AES_BLOCK_SIZE)] # divide into blocks
    result = bytes()

    # P2 - Iteration over block. From c[n] -> c[n-1] -> ... -> c[1].
    for block_i in range(len(blocks) - 1, 0, -1):
        c_curr_block = blocks[block_i]                    # c[i]
        c_prev_block = blocks[block_i - 1]                # c[i-1]
        d_current_block  = bytearray(AES_BLOCK_SIZE)      # d[i]
        modified_c_prev_block = bytearray(c_prev_block)   # c[i-1]

        # P3 - Iteration over byte. From p[i][15] -> p[i][14] -> ... p[i][0].
        for byte_idx in range(AES_BLOCK_SIZE - 1, -1, -1):
            padding = AES_BLOCK_SIZE - byte_idx

            # P4 - Modified padding. From index 15 -> 15,14 -> 15,14,13...
            for i in range(AES_BLOCK_SIZE - padding, AES_BLOCK_SIZE):
                modified_c_prev_block[i] = c_prev_block[i] ^ d_current_block[i] ^ padding

            # P5 - Iteration over every possible byte.
            for bit in range(256):
                modified_c_prev_block[byte_idx] = bit
                candidate_case = bytes(modified_c_prev_block) + c_curr_block

                # Check if server() return True.
                if server(candidate_case):
                    # Validate FP.
                    if padding == 1 and byte_idx > 0:
                        modified_c_prev_block[byte_idx - 1] ^= 1
                        if not server(bytes(modified_c_prev_block) + c_curr_block):
                            modified_c_prev_block[byte_idx - 1] ^= 1
                            continue
                    d_current_block[byte_idx] = modified_c_prev_block[byte_idx] ^ padding ^ c_prev_block[byte_idx]
                    break

        result  = bytes(d_current_block) + result

    return result[:-result[-1]]


def find_cookie_length(device):
    """
    Determines the length (in bytes) of a secret cookie that the device appends to a plaintext message
    before encryption.

    Parameters:
        device (function): A stateful CBC encryption oracle with the signature:
                               device(path: bytes) -> bytes
                           The device takes a bytes object "path" as input and internally constructs a message:
                               msg = path + b";cookie=" + cookie
                           It then pads and encrypts this message using AES in CBC mode.
                           Importantly, the device retains its CBC state between calls, so the encryption is stateful.

    Returns:
        int: The length of the secret cookie (in bytes).
    """
    # msg = "PPPPPPPP" + ";cookie=" + cookie
    # msg = len(path) + 8 + ?

    path = b""
    len_no_path = len(device(path))  # No path added, base length.

    while True:
        # Add 1 byte every time. And get new length with path-added msg.
        path += b"P"
        len_new_path = len(device(path))
        # Check if there's a new block shows up. If yes, then we know the msg's mod 16 is 0.
        if len_new_path > len_no_path:
            # print("find a new block !!!!! ", len_new_path, path, len(path), len_cookie)
            len_cookie = len_no_path - len(path) -  8 # Get cookie's length.
            return len_cookie


def find_cookie(device):
    """
    Recovers the secret cookie that the device appends to the plaintext message before encryption.

    Parameters:
        device (function): A stateful CBC encryption oracle with the signature:
                               device(path: bytes) -> bytes
                           The device builds the message as:
                               msg = path + b";cookie=" + cookie
                           and then pads and encrypts msg using AES in CBC mode, while maintaining the CBC chaining
                           state across calls.

    Returns:
        bytes: The secret cookie that was appended to the plaintext.
    """
    # P1 - Extract cookie length. Decrypt b";cookie=" + cookie.
    cookie_length = find_cookie_length(device)
    decrypt_part_length = cookie_length + 8
    block_number = decrypt_part_length // 16 + 2
    result = b""

    # P2 - User empty path to generate an initial cipher text. Extract last 16 digits as IV.
    initial_ctx = device(b"")
    initial_iv = initial_ctx[-AES_BLOCK_SIZE:]

    # P3 - Helper method to XOR on the block.
    def xor_block(p, iv):
        block_xor = bytearray(AES_BLOCK_SIZE)
        for i in range(AES_BLOCK_SIZE):
            block_xor[i] = p[i] ^ iv[i]
        ret = bytes(block_xor) + p[AES_BLOCK_SIZE:]
        return ret

    first_path_length = block_number * AES_BLOCK_SIZE - 1

    first_path = b""
    for i in range(first_path_length): first_path += b"P"
    print(f"first_path={first_path}")

    xor_result = xor_block(first_path, initial_iv) # With initial iv,

    first_ctx = device(xor_result)

    prev_iv = first_ctx[-AES_BLOCK_SIZE:]


    # P4 - Iteration over every byte needed to be decrypted.
    for byte_idx in range(1, decrypt_part_length + 1):
        path_length = block_number * AES_BLOCK_SIZE - byte_idx
        path = b""
        for i in range(path_length): path += b"P"
        xor_result = xor_block(path, prev_iv)
        ctx = device(xor_result)
        prev_iv = ctx[-AES_BLOCK_SIZE:]

        start = (block_number - 1) * AES_BLOCK_SIZE
        end   = start + AES_BLOCK_SIZE
        baseline = ctx[start:end] # select a baseline to compare.

        # P5 - BF over each possible byte.
        for byte in range(256):
            msg = path + result + bytes([byte])
            xor_bf = xor_block(msg, prev_iv)
            ctx = device(xor_bf)
            prev_iv = ctx[-AES_BLOCK_SIZE:]

            # P6 - Compare result candidate.
            if ctx[start:end] == baseline:
                result = result + bytes([byte])
                break

    result = result[-cookie_length:]
    return result
