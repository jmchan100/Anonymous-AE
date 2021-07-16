from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# PRF that uses a block cipher with truncation
def prf(cipher, length, message):
    output = cipher.update(message)
    return output[:length]

