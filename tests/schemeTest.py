import os
import random
from time import clock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from utilities import hexstring, intToNonce, nonceInc
from policy import SimplePolicy, PolicyFunction, addToHistory
from scheme import BaseState, aAEBase, DictState, aAEDict, NaiveState, aAENaive, nAEScheme
from scheme import NonceWrapState, NonceWrap

# registers number of users with the aAE scheme
def aAESchemeTestSetup(numUsers=1, policy=None, schemeName="base", verbose=False):

    if schemeName == "base":
        if not isinstance(policy, PolicyFunction):
            policy = SimplePolicy()
        scheme = aAEBase(verbose=verbose, policy=policy)
        state = BaseState()
    elif schemeName == "dict":
        if not isinstance(policy, PolicyFunction):
            policy = SimplePolicy(16)
        scheme = aAEDict(verbose=verbose, policy=policy)
        state = DictState()
    elif schemeName == "naive":
        if not isinstance(policy, PolicyFunction):
            policy = SimplePolicy(16)
        scheme = aAENaive(verbose=verbose, policy=policy)
        state = NaiveState()
        labels = []
        keys = []
        for i in range(numUsers):
            key = os.urandom(scheme.keyLen)
            keys.append(key)
            (label, state) = scheme.initialize(key, state)
            labels.append(label)
        return (scheme, labels, keys, state)
    elif schemeName == "NonceWrap":
        if not isinstance(policy, PolicyFunction):
            policy = SimplePolicy()
        scheme = NonceWrap(lx=policy, nx=policy)
        state = NonceWrapState()
        labels = []
        keys = []
        for i in range(numUsers):
            nonceKey = os.urandom(scheme.nonceKeyLen)
            aeKey = AESGCM.generate_key(bit_length=scheme.aeadKeyLen*8)
            key = nonceKey + aeKey
            keys.append(key)

            (label, state) = scheme.initialize(key, state)
            labels.append(label)
        return (scheme, labels, keys, state)
    else:
        return None

    labels = []
    keys = []

    for i in range(numUsers):
        nonceKey = os.urandom(scheme.nonceKeyLen)
        ADKey = os.urandom(scheme.ADKeyLen)
        aeKey = AESGCM.generate_key(bit_length=scheme.aeadKeyLen*8)
        key = nonceKey + ADKey + aeKey
        keys.append(key)

        (label, state) = scheme.initialize(key, state)
        labels.append(label)

    return (scheme, labels, keys, state)

def aAEEncryptTest(scheme, key=None,nonce=None,AD=None,msg=None):
    if key == None:
        nonceKey = os.urandom(scheme.nonceKeyLen)
        ADKey = os.urandom(scheme.ADKeyLen)
        aeKey = AESGCM.generate_key(bit_length=scheme.aeadKeyLength*8)
        key = nonceKey + ADKey + aeKey

    if nonce == None:
        nonce = os.urandom(scheme.nonceLen)

    if AD == None:
        AD = ""

    if msg == None:
        msg = ""

    return scheme.enc(key, nonce, AD, msg)

def aAEDecryptTest(scheme, ciphertext, state):
    return scheme.dec(ciphertext, state)

# Test a scheme
# numUsers - The number of senders communicating
# policy - The nonce policy the communication is operating under, default is SimplePolicy
# schemeName - Either "base" or "dict", default is "base"
# maxNonces - The number of valid nonces that we may send at a time,
#             it accounts for policies that may return a large set of nonces
#             and selects maxNonces number of them to send
# rounds - How many rounds of communication are there?
#          A round consists of encrypting messages and storing them in a list,
#          shuffling the list,
#          then decrypting those messages
def schemeTest1(numUsers, policy=None, schemeName="base", maxNonces=2, rounds=1, verbose=True):

    # Instantiate scheme
    try:
        (scheme, labels, keys, state) = aAESchemeTestSetup(numUsers=numUsers,
                policy=policy, schemeName=schemeName)
    except:
        print "Invalid scheme name: " + schemeName
        print "Valid names: base, dict, naive"
        return

    state = scheme.asso("", state)
    ctexts = {}
    nonces = {}

    # Encrypt and decrypt rounds number of times
    for i in range(rounds):
        if verbose:
            print "-----------------Encrypting round " + str(i) + "--------------------"
        for (label,key) in zip(labels,keys):
            valid = scheme.policy.applyPolicy(nonces.setdefault(label,[]))
            for i in range(maxNonces):
                try:
                    nonce = valid.pop()
                    ctexts[label] = aAEEncryptTest(scheme, key=key, nonce=nonce, msg=str(label))
                    nonces[label] = addToHistory(scheme.policy, nonce, nonces[label])
                    if verbose:
                        print hexstring(ctexts[label])
                except KeyError:
                    pass
        if verbose:
            print "------------------------------Decrypting-------------------------------"
        lbls = ctexts.keys()
        random.shuffle(lbls)

        for lbl in lbls:
            ret = aAEDecryptTest(scheme,ctexts[lbl], state)
            if ret is not None:
                (L,N,A,M,state) = ret
                if verbose:
                    print "(l,N,A,M,S): " + str((L,N,A,M))
            else:
                if verbose:
                    print "(l,N,A,M,S): None"

# Measures speed of decrypting one message with some number of sessions
# numUsers - The number of session keys
# msgSize - The size of the message to encrypt/decrypt in bytes
# policy - The nonce policy the communication is operating under, default is SimplePolicy
# maxNonces - The number of valid nonces that we may send at a time,
#             it accounts for policies that may return a large set of nonces
#             and selects maxNonces number of them to send
def schemeSpeedTest(numUsers=100, msgSize=4096, schemeName="base", policy=None, rounds=1, seed=1):

    # Instantiate scheme
    try:
        (scheme, labels, keys, state) = aAESchemeTestSetup(numUsers=numUsers,
                policy=policy, schemeName=schemeName)
    except:
        print "Invalid scheme name: " + schemeName
        print "Valid names: base, dict, naive"
        return

    # So we can test the same sender order
    random.seed(seed)

    nonces = {}
    for label in labels:
        state = scheme.asso("", state, label=label)
    msg = "\x00"*msgSize
    times = []
    time = 0.0

    for n in range(rounds):
        # Pick a random sender
        i = random.choice(range(numUsers))

        nonce = scheme.policy.applyPolicy(nonces.setdefault(labels[i],[])).pop()
        ctext = scheme.enc(keys[i], nonce, "", msg)

        x = clock()
        (l, n, a, m, state) = scheme.dec(ctext, state)
        y = clock()
        times.append(y-x)
        nonces[labels[i]].append(n)
        time += (y-x)
        if m != msg or l != i:
            raise Exception("Decryption failed")

    #times.sort()
    return time
    #return times


# Test the speed of plain old nAE scheme
# keyLength - Length of the key in bytes
# msgSize - The size of the message to encrypt/decrypt in bytes
def naeSpeedTest(keyLength=32, msgSize=4096, rounds=1):
    key = AESGCM.generate_key(bit_length=keyLength*8)
    AD = "AD"
    msg = "\x00"*msgSize
    nae = nAEScheme(key)

    times = []
    time = 0.0

    for n in range(rounds):
        nonce = os.urandom(12)
        ctext = nae.enc(nonce, AD, msg)

        x = clock()
        msg2 = nae.dec(nonce, AD, ctext)
        y = clock()
        times.append(y-x)
        time += (y-x)
        if msg2 != msg:
            raise Exception("Decryption failed")

    #times.sort()
    return time
    #return times

# Test a scheme's disa function
# Decryption should fail after calling disa on the necessary AD
def schemeDisaTest(schemeName="base",verbose=True):
    try:
        (scheme, labels, keys, state) = aAESchemeTestSetup(numUsers=2, schemeName=schemeName)
    except:
        print "Invalid scheme name: " + schemeName
        print "Valid names: base, dict"
        return

    state = scheme.asso("AD", state)
    valid = scheme.policy.applyPolicy([])
    nonce = random.choice(tuple(valid))

    AD1 = "AD" + str(labels[0])
    AD2 = "AD" + str(labels[1])

    state = scheme.asso(AD1, state, labels[0])
    state = scheme.asso(AD2, state, labels[1])

    if verbose:
        print "######################### Added ADs to state ##########################"
        print "Default ADs: " + str(state.defaultADs)
        print "Label ADs: " + str(state.labelADs)

    state = scheme.disa("AD", state)
    state = scheme.disa(AD1, state, labels[0])

    if verbose:
        print "######################### Removed ADs from state ##########################"
        print "Default ADs: " + str(state.defaultADs)
        print "Label ADs: " + str(state.labelADs)

    ct1 = aAEEncryptTest(scheme, key=keys[0], nonce=nonce, AD=AD1, msg="")
    ct2 = aAEEncryptTest(scheme, key=keys[1], nonce=nonce, AD=AD2, msg="")

    # msg1 is expected to be None, msg2 is expected to be a valid tuple
    msg1 = aAEDecryptTest(scheme, ct1, state)
    msg2 = aAEDecryptTest(scheme, ct2, state)

    if verbose:
        print str(msg1)
        print str(msg2)

# Test the dictionary scheme's term function
# Checks to see if the headers associated with a label have been removed
# Checks to see that the ciphertext for that label can't be decrypted anymore
def schemeTermTest(schemeName="base",verbose=True):
    try:
        (scheme, labels, keys, state) = aAESchemeTestSetup(numUsers=2, schemeName=schemeName)
    except:
        print "Invalid scheme name: " + schemeName
        print "Valid names: base, dict"

    state = scheme.asso("", state)
    valid = scheme.policy.applyPolicy([])
    nonce = random.choice(tuple(valid))

    ct1 = aAEEncryptTest(scheme, key=keys[0], nonce=nonce, AD="", msg="bad")
    ct2 = aAEEncryptTest(scheme, key=keys[1], nonce=nonce, AD="", msg="good")

    state = scheme.term(labels[0], state)
    if verbose:
        print "######################## Terminated session for key 0 ##########################"

    if schemeName == "dict":
        if verbose:
            print "Header dictionary:"
            print state.dict

    if verbose:
        print "######################## Trying to decrypt ##########################"
    msg1 = aAEDecryptTest(scheme, ct1, state)
    msg2 = aAEDecryptTest(scheme, ct2, state)

    if verbose:
        print str(msg1)
        print str(msg2)


# Not called, was used to check nonce values outside of the scope of
# the scheme's decryption for debugging
def nonceCheck(scheme, ciphertexts, keys):
    print "----------------------- Checking nonces outside of scheme -----------------------"
    nHdrLen = scheme.nonceHdrLen
    bcs = []
    for key in keys:
        k = key[:scheme.nonceKeyLen]
        bcs.append(Cipher(algorithms.AES(k), modes.ECB(), default_backend()).decryptor())

    for i in ciphertexts.keys():
        nHdr = ciphertexts[i][:nHdrLen]
        nonce = bcs[i].update(nHdr)
        #print "####################### Checking header #######################"
        #print hexstring(nHdr)
        #print "####################### Resulting nonce #######################"
        #print hexstring(nonce)

# Tests NonceWrap
# numUsers - The number of senders communicating
# nx - The nonce policy the communication is operating under, default is SimplePolicy
# lx - The nonce anticipation the communication is operating under, default is SimplePolicy
# maxNonces - The number of valid nonces that we may send at a time,
#             it accounts for policies that may return a large set of nonces
#             and selects maxNonces number of them to send
# rounds - How many rounds of communication are there?
#          A round consists of encrypting messages and storing them in a list,
#          shuffling the list,
#          then decrypting those messages
def NWTest(numUsers=100, msgSize=4096, nx=None, lx=None, maxNonces=2, rounds=1, seed=1):

    # Instantiate scheme
    (scheme, labels, keys, state) = aAESchemeTestSetup(numUsers=numUsers,
            policy=nx, schemeName="NonceWrap")

    # So we can test the same sender order
    random.seed(seed)

    nonces = {}
    for label in labels:
        state = scheme.asso("", state, label=label)
    msg = "\x00"*msgSize
    times = []
    time = 0.0


    for n in range(rounds):
        # Pick a random sender
        i = random.choice(range(numUsers))

        nonce = scheme.lx.applyPolicy(nonces.setdefault(labels[i],[])).pop()
        ctext = scheme.enc(keys[i], nonce, "", msg)

        x = clock()
        (l, n, a, m, state) = scheme.dec(ctext, state)
        y = clock()
        times.append(y-x)
        nonces[labels[i]].append(n)
        time += (y-x)
        if m != msg or l != i:
            raise Exception("Decryption failed")

    return time

