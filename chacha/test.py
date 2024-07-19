from chacha20 import ChaCha20
import hashlib
from base64 import b64encode, b64decode
import binascii
#from Crypto.Cipher import ChaCha20

#octet_string = """00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:
#0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"""
#octet_string = octet_string.replace(":", "")
#key = bytes.fromhex(octet_string)
#octet_string = "00:00:00:00:00:00:00:4a:00:00:00:00"
#octet_string = octet_string.replace(":", "")
#nonce = bytes.fromhex(octet_string)

#plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

#cipher = ChaCha20(key, nonce)

#ciphertext = cipher.encrypt(plaintext.encode())
#print(binascii.hexlify(ciphertext).decode())

#cipher.block_counter = 0
#plain = cipher.decrypt(ciphertext).decode()
#print(plain)


#octet_string = """00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"""
#octet_string = octet_string.replace(":", "")
#key = bytes.fromhex(octet_string)
#octet_string = "00:00:00:00:00:00:00:4a:00:00:00:00"
#octet_string = octet_string.replace(":", "")
#nonce = bytes.fromhex(octet_string)
#plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

#cipher = ChaCha20.new(key=key, nonce=nonce)
#byte_array = bytearray(64)
#cipher.encrypt(byte_array)
#ciphertext = cipher.encrypt(plaintext.encode())
#print(binascii.hexlify(ciphertext).decode())


def get_key(key):
    hash_key  = hashlib.sha256()
    hash_key.update(key)
    return hash_key.digest()

print("e".encode()[0])
key = get_key("q".encode())
cipher = ChaCha20(key, b64decode("IHAR7o82uyZGPqZn"))

print(cipher.decrypt(b64decode("3WGvPVQ=")).decode('utf-8'))
