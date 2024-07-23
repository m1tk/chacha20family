from chacha20 import ChaCha20
from poly1305 import poly1305_tag
import struct

class ChaCha20Poly1305():
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        self.key = key

    def poly1305_keygen(self, key, nonce):
        poly = ChaCha20(key, nonce)
        return poly.encrypt(bytearray(32))

    def pad16(self, data):
        if len(data) % 16 == 0:
            return bytearray(0)
        else:
            return bytearray(16-(len(data)%16))

    def encrypt(self, nonce, plaintext, aad=None):
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")
        if aad is None:
            aad = bytearray(0)

        auth_key = self.poly1305_keygen(self.key, nonce)
        
        cipher = ChaCha20(self.key, nonce)

        # always start from 1
        cipher.block_counter = 1

        ciphertext = cipher.encrypt(plaintext)
        print(binascii.hexlify(ciphertext).decode())

        # | aad | padding aad | ciphertext | padding cipher text | aad len 8 byte | cipher len 8 byte | tag 16 byte

        auth_msg   = aad
        auth_msg  += self.pad16(aad)
        auth_msg  += ciphertext
        auth_msg  += self.pad16(ciphertext)
        auth_msg  += struct.pack('<Q', len(aad))
        auth_msg  += struct.pack('<Q', len(ciphertext))

        auth_msg  += poly1305_tag(auth_key, auth_msg)

        return auth_msg

    def decrypt(self, nonce, ciphertext, aad=None):
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")
        if aad is None:
            aad = bytearray(0)
        if len(ciphertext) < 32:
            # we must have at least aad and ciphertext lengths and tag
            return None
        
        msg_tag    = ciphertext[-16:]
        size_cip   = int.from_bytes(ciphertext[-24:-16], byteorder='little')
        size_aad   = int.from_bytes(ciphertext[-32:-24], byteorder='little')
        print(size_cip)
        size_pad   = 16-(size_cip%16)
        ciphertext = ciphertext[(-(32+size_pad+size_cip)):-(32+size_pad)]
        print(binascii.hexlify(ciphertext).decode())

        auth_key = self.poly1305_keygen(self.key, nonce)

        auth_msg   = aad
        auth_msg  += self.pad16(aad)
        auth_msg  += ciphertext
        auth_msg  += self.pad16(ciphertext)
        auth_msg  += struct.pack('<Q', len(aad))
        auth_msg  += struct.pack('<Q', len(ciphertext))
        tag        = poly1305_tag(auth_key, auth_msg)

        if tag != msg_tag:
            raise ValueError("Invalid tag")
        
        cipher = ChaCha20(self.key, nonce)
        cipher.block_counter = 1

        return cipher.decrypt(ciphertext)

"""

import binascii

octet_string = "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"
octet_string = octet_string.replace(" ", "")
key = bytes.fromhex(octet_string)
octet_string = "07 00 00 00 40 41 42 43 44 45 46 47"
octet_string = octet_string.replace(" ", "")
nonce = bytes.fromhex(octet_string)
octet_string = "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7"
octet_string = octet_string.replace(" ", "")
aad = bytes.fromhex(octet_string)

plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

aead = ChaCha20Poly1305(key)
k = aead.encrypt(nonce, plaintext.encode(), aad)
print(aead.decrypt(nonce, k, aad).decode())
"""
