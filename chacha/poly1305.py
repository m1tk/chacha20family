
P = 0x3fffffffffffffffffffffffffffffffb # 2^130-5

def ceildiv(a, b):
    return -(-a // b)

def num_to_16_le_bytes(num):
    """Convert number to 16 bytes in little endian format"""
    ret = [0]*16
    for i, _ in enumerate(ret):
        ret[i] = num & 0xff
        num >>= 8
    return bytearray(ret)

def poly1305_tag(key, msg):
    if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
    a = 0
    r = int.from_bytes(key[0:16], byteorder='little')
    # clamping r
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], byteorder='little')
    # now we calculate tag
    for i in range(0, ceildiv(len(msg), 16)):
        n = int.from_bytes(msg[i*16:(i+1)*16] + b'\x01', byteorder='little') 
        a += n
        a = (r * a) % P
    a += s
    return num_to_16_le_bytes(a)
