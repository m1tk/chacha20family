import numpy as np
import struct
from textwrap import wrap
import binascii

# overflow is not a problem
np.seterr(over='ignore')

def quarter_round(a, b, c, d):
    a = (a + b)
    d = (d ^ a)
    d = (d << 16 | d >> 16)
    c = (c + d)
    b = (b ^ c)
    b = (b << 12 | b >> 20)
    a = (a + b)
    d = (d ^ a)
    d = (d << 8 | d >> 24)
    c = (c + d)
    b = (b ^ c)
    b = (b << 7 | b >> 25)
    return a, b, c, d

def rounds(state):
    steps = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14],
    ]
    for _ in range(10):
        for r in steps:
            state[r] = quarter_round(*(state[r]))
    return state

def init(key, nonce):
    # Declaring state
    # Here we are using fixed size int to handle overflow edge cases
    state = np.empty(shape=16, dtype=np.uint32)
    state[:4] = np.array([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574], dtype=np.uint32)
    # 4..11 from the key
    state[4:12] = struct.unpack("<8L", key)
    state[12]   = 0
    # nonce
    state[13:]  = struct.unpack("<3L", nonce)

    return state

def block_fn(init):
    init[12] += 1
    print_state(init)
    state     = rounds(init.copy())
    state     = state + init
    print_state(state)
    return state
    
def encrypt(state, plaintext):
    # calling block function
    state      = block_fn(state)
    # serializing final state
    stream     = struct.pack("<16L", *state)
    # XOR
    ciphertext = bytes([a ^ b for a, b in zip(stream, plaintext)])
    # returning only size of plaintext
    return ciphertext[:len(plaintext)]

def decrypt(state, ciphertext):
    return encrypt(state, ciphertext)

def print_state(state):
    for i in range(0, 4):
        for j in range(0, 4):
            print(hex(state[i * 4 + j]), "\t\t", end="")
        print()
    print()

def main():
    octet_string = """00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:
0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"""
    octet_string = octet_string.replace(":", "")
    key = bytes.fromhex(octet_string)
    octet_string = "00:00:00:00:00:00:00:4a:00:00:00:00"
    octet_string = octet_string.replace(":", "")
    nonce = bytes.fromhex(octet_string)

    sinit = init(key, nonce)

    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    for block in wrap(plaintext, width=64):
        k = encrypt(sinit, block.encode())
        print(binascii.hexlify(k).decode())


main()
