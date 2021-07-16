import struct, string, random

# Contains utility functions

MAXINT32 = 0xFFFFFFFF
MAXINT64 = 0xFFFFFFFFFFFFFFFF

# Creates a random alphabetical string of length length
def randString(length):
    return ''.join(random.choice(string.lowercase) for x in range(length))


# Turns a string into a string of hex values delimited by the ':' character
def hexstring(string, delimiter=':'):
    return delimiter.join(x.encode('hex') for x in string)

# Returns the xor of two strings a and b
def stringXor(a, b):
    return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))

# Turns an int represented by hi and lo to a nonce
# hi is the higher order bits and lo is the lower order bits
def intToNonce(length, hi=0, lo=0):
    fmt = determineFormat(length)
    return struct.pack(fmt, hi, lo)

# Determines the format depending on the length of a nonce
# to be used with struct pack and unpack
def determineFormat(length):
    if length == 12:
        return ">IQ"
    elif length == 16:
        return ">QQ"

    return None

# Increments a nonce based on nonce length
def nonceInc(nonce):
    fmt = determineFormat(len(nonce))

    (numHI, numLO) = struct.unpack(fmt, nonce)

    length = len(nonce)
    if numLO == MAXINT64:

        # Throw exception
        if (length == 12 and numHI == MAXINT32) or (length == 16 and numHI == MAXINT64):
            print "This nonce has reached its maximum value"
            return None

        numLO = 0
        numHI = numHI+1
    else:
        numLO += 1

    return struct.pack(fmt, numHI, numLO)
