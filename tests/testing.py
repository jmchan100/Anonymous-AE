import os
import sys
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from prf import prf
from utilities import randString

maxint64 = 0xFFFFFFFFFFFFFFFF

def hexstring(string):
    return ':'.join(x.encode('hex') for x in string)

def getTestBC(key=None):
    backend = default_backend()

    if key is None:
        key = AESGCM.generate_key(bit_length=256)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend)
    return (cipher, key)

def prfTest(key=None, length=12):
    (cipher,key) = getTestBC(key)
    msg = randString(16)
    prfOut = prf(cipher, length, msg)
    return (prfOut, msg, key)

def hashTest():
    hashFn = hashes.Hash(hashes.SHA256(), backend=default_backend())

def test1():
    backend = default_backend()
    #key = os.urandom(32)
    key = '1234567891234567'
    print str(key)
    #iv = os.urandom(16)

    inpt1 = struct.pack(">QQ", 0, 0)
    inpt2 = struct.pack(">QQ", 0, 0)
    # ECB mode here -- we're only ever using this to encode a nonce <= the block size
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend)
    enc = cipher.encryptor()
    ct1 = enc.update(inpt1)
    ct2 = enc.update(inpt2)
    hexct1 = ':'.join(x.encode('hex') for x in ct1)
    print hexct1
    print str(ct2)

    dec = cipher.decryptor()
    pt1 = dec.update(ct1)
    pt2 = dec.update(ct2)
    print str(pt1)
    print str(pt2)

def test2():
    #backend = default_backend()
    key = AESGCM.generate_key(bit_length=256)
    #key = '1234567891234567'
    print str(key)

    aesgcm = AESGCM(key)
    aesgcm2 = AESGCM(key)

    n = 0

    nonce = struct.pack(">Q", n)
    inpt = 'this is a message'
    aad = 'ad for message'
    ct = aesgcm.encrypt(nonce, inpt, aad)
    print ct

    try:
        pt = aesgcm.decrypt(nonce,ct,inpt)
    except InvalidTag:
        print "Decryption failed, retrying with actual AD"
    print pt

    n += 1
    nonce = struct.pack(">Q", n)
    ct = aesgcm.encrypt(nonce, inpt, aad)
    print ct
    pt = aesgcm2.decrypt(nonce,ct,aad)
    print pt


class testState(object):

    def __init__(self):
        self.lbl = 0
        self.keys = {}
        self.used = set()
        self.nonces = {}
        self.ADs = {}
