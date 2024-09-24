import numpy as np
import struct
import binascii
from chacha.chacha20 import ChaCha20

def chunked(size, source):
    for i in range(0, len(source), size):
        yield source[i:i+size]


# overflow is not a problem
np.seterr(over='ignore')
class XChaCha20():
    def __init__(self, key, nonce):
        self.key = HChaCha20(key, nonce[0:16]).get_state()
        self.nonce = b"\x00\x00\x00\x00" + nonce[16:24]
        self.ChaCha20 = ChaCha20(self.key,self.nonce)

    def encrypt(self, plaintext):
        return self.ChaCha20.encrypt(plaintext)
    
    def decrypt(self, ciphertext):
        return self.ChaCha20.decrypt(ciphertext)

class HChaCha20():
    def __init__(self, key, nonce):
        # Declaring state
        # Here we are using fixed size int to handle overflow edge cases
        state       = np.empty(shape=16, dtype=np.uint32)
        state[:4]   = np.array([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574], dtype=np.uint32)
        # 4..11 from the key
        state[4:12] = struct.unpack("<8L", key)
        # nonce
        state[12:]  = struct.unpack("<4L", nonce)

        self.state  = state
        self.state  = self.rounds(self.state.copy())

    def get_state(self):

        s = b''.join(struct.pack('<I', num) for num in self.state[0:4]) + b''.join(struct.pack('<I', num) for num in self.state[12:16])
        return s


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
