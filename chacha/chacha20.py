import numpy as np
import struct

def chunked(size, source):
    for i in range(0, len(source), size):
        yield source[i:i+size]


# overflow is not a problem
np.seterr(over='ignore')

class ChaCha20():
    def __init__(self, key, nonce):
        self.block_counter = 0
        # Declaring state
        # Here we are using fixed size int to handle overflow edge cases
        state = np.empty(shape=16, dtype=np.uint32)
        state[:4] = np.array([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574], dtype=np.uint32)
        # 4..11 from the key
        state[4:12] = struct.unpack("<8L", key)
        state[12]   = self.block_counter
        # nonce
        state[13:]  = struct.unpack("<3L", nonce)

        self.state = state

    def quarter_round(self, a, b, c, d):
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

    def rounds(self, state):
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
                state[r] = self.quarter_round(*(state[r]))
        return state

    def block_fn(self):
        self.state[12] = self.block_counter
        state     = self.rounds(self.state.copy())
        state     = state + self.state
        self.block_counter += 1
        return state
        
    def encrypt_inner(self, plaintext):
        # calling block function
        state      = self.block_fn()
        # serializing final state
        stream     = struct.pack("<16L", *state)
        # XOR
        ciphertext = bytes([a ^ b for a, b in zip(stream, plaintext)])
        print(len(ciphertext))
        # returning only size of plaintext
        return ciphertext
    
    def encrypt(self, plaintext):
        chunk = b''
        for i in chunked(64, plaintext):
            chunk += self.encrypt_inner(i)
        return chunk


    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)
