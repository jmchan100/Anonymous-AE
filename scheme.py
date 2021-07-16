import os
import abc
from random import SystemRandom
from enum import Enum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag, InternalError

from utilities import hexstring, stringXor, nonceInc
from prf import prf
from policy import PolicyFunction, SimplePolicy, addToHistory

# Stateless nAE scheme, basically just a wrapper for AESGCM
class nAEScheme(object):

    def __init__(self, key):
        self.scheme = AESGCM(key)

    def enc(self, nonce, AD, message):
        return self.scheme.encrypt(nonce, message, AD)

    def dec(self, nonce, AD, ciphertext):
        return self.scheme.decrypt(nonce, ciphertext, AD)

# Abstract class for aAE Schemes.
class aAEScheme(object):
    __metaclass__ = abc.ABCMeta

    # Registers new key with the scheme. Updates the state accordingly.
    # Param - key (bytes) - The key to register with the scheme>
    # Param - state (state object) - Current state of the scheme.
    # Return - (int, state) - A unique label associated with the key and the updated state.
    @abc.abstractmethod
    def initialize(self, key, state):
        pass

    # Terminates the session associated with the label. Updates the state accordingly.
    # Param - label (int) - The label to delete and remove from the scheme.
    # Param - state (state object) - The current state of the scheme.
    # Return - state - updated state
    @abc.abstractmethod
    def term(self, label, state):
        pass

    # Adds an associated data to use with a specified label. Updates the state accordingly.
    # If the label is omitted, the AD will be associated globally,
    # meaning that it applies to all sessions.
    # This AD is intended to be used by future decryption calls.
    # Param - AD (byte) - The associated data for future use.
    # Param - label (int) - The label to add the AD under.
    # Param - state (state object) - Current state of the scheme.
    # Return - state - updated state.
    @abc.abstractmethod
    def asso(self, AD, state, label):
        pass

    # Removes association between AD and specified label. Updates the state accordingly.
    # If the label is omitted, the AD will be disassociated globally,
    # meaning that it is removed from the set of ADs that apply across sessions.
    # Param - AD (byte) - The associated data to remove.
    # Param - label (int) - The label to disassociate the AD from.
    # Param - state (state object) - Current state of the scheme.
    # Return - state - updated state.
    @abc.abstractmethod
    def disa(self, AD, state, label):
        pass

    # Stateless encryption function that encrypts a message under the specified key, nonce, and AD.
    # Param - key (byte) - The key to perform the encryption under.
    # Param - nonce (byte) - The nonce to use with encryption.
    # Param - AD (byte) - The AD to use with encryption.
    # Param - message (byte) - The message to be encrypted.
    # Return - byte - The ciphertext resulting from the encryption of the message.
    @abc.abstractmethod
    def enc(self, key, nonce, AD, message):
        pass

    # Stateful decryption function that attempts to decrypt a ciphertext
    # based on the context that the current state provides.
    # Param - ciphertext (byte) - The ciphertext to decrypt.
    # Param - state (state object) - Current state of the scheme.
    # Return - (int, byte, byte, state) - The label associated with the key of the ciphertext.
    #                                   - The nonce used to recover the message.
    #                                   - The message recovered from the ciphertext.
    #                                   - The updated state.
    @abc.abstractmethod
    def dec(self, ciphertext, state):
        pass

#################################################################
# Naive Scheme
#################################################################
# State object for naive scheme
class NaiveState(object):

    def __init__(self):

        # Counter for creating unique labels on reg() calls.
        self.lblCtr = 0

        self.AEADs = {}       # AEAD schemes used to decrypt ciphertexts

        self.keys = {}        # Session's AEAD keys
        self.nonceDec = {}    # Session to nonce history mappings

        # ADs associated to a label, dictionary mapping labels to sets of ADs
        self.labelADs = {}

        # ADs associated across sessions contained in a set
        self.defaultADs = set()

        # Keeps track of which labels are currently in use.
        self.labels = set()

# Naive scheme with no headers. Just iterates through every
# possible session, nonce, and AD when decrypting
class aAENaive(aAEScheme):

    # Initializes the baseline scheme with information regarding the
    # details of the algorithms that it will use
    def __init__(self, keyLen=32, nonceLen=16, policy=None, simpleStart=True, verbose=False):
        self.keyLen = keyLen                                    # key for aead scheme

        if isinstance(policy, PolicyFunction):
            self.policy = policy                                # nonce policy
        else:
            self.policy = SimplePolicy(nonceLength=self.nonceLen)

        self.simpleStart = simpleStart
        self.nonceLen = nonceLen                                # length of nonces for scheme
        self.verbose = verbose                                  # debug messages

    def initialize(self, key, state):
        label = state.lblCtr
        state.lblCtr += 1
        state.keys[label] = key

        state.AEADs[label] = AESGCM(key)

        state.labels.add(label)
        state.nonceDec[label] = []
        state.labelADs[label] = set()
        return (label,state)

    def term(self, label, state):
        # The label must exist
        try:
            state.keys.pop(label)
            state.AEADs.pop(label)
            state.labelADs.pop(label)
            state.nonceDec.pop(label)
            state.labels.remove(label)
        except KeyError:
            pass
        return state


    def asso(self, AD, state, label=None):
        if label not in state.labels and label is not None:
            return state

        if label is None:
            state.defaultADs.add(AD)
        else:
            state.labelADs[label].add(AD)

        return state


    def disa(self, AD, state, label=None):
        if label not in state.labels and label is not None:
            return state

        if label is None:
            state.defaultADs.remove(AD)
        else:
            try:
                state.labelADs.setdefault(hashedAD,{}).setdefault(hashedAD,set()).remove(AD)
            except KeyError:
                pass
        return state


    # No headers in naive scheme
    def enc(self, key, nonce, AD, message):
        return AESGCM(key).encrypt(nonce, message, AD)

    def dec(self, ciphertext, state):
        if self.simpleStart:
            start = 0
        else:
            # Randomize starting point of iteration
            gen = SystemRandom()
            start = gen.randrange(state.lblCtr)

        # Iterate through each active label
        for i in range(start, start + state.lblCtr):
            label = i % state.lblCtr
            if label not in state.labels:
                continue

            # Tries every nonce belonging to label
            for nonce in self.policy.applyPolicy(state.nonceDec[label]):
                for AD in state.labelADs[label].union(state.defaultADs):
                    try:
                        msg = state.AEADs[label].decrypt(nonce, ciphertext, AD)

                        # Update decryption history
                        state.nonceDec[label] = addToHistory(self.policy, nonce, state.nonceDec[label])
                        #state.nonceDec[label].append(nonce)
                        #if len(state.nonceDec[label]) > self.policy.domain:
                        #    state.nonceDec[label] = state.nonceDec[label][:-1]
                        return (label, nonce, AD, msg, state)
                    except (InvalidTag,InternalError):
                        continue
        return None

###############################################################
# Baseline Scheme
###############################################################

# State object for the baseline scheme.
class BaseState(object):

    def __init__(self):

        # Counter for creating unique labels on reg() calls.
        self.lblCtr = 0

        # Used in place of the key as the cipher and AEAD are instantiated using the key.
        self.nonceBCs = {}    # Block ciphers used in generating nonce header
        self.nonceBCInvs = {} # The inverses of the block ciphers (storing this should save time)
        self.ADBCs = {}       # Block ciphers used in the prf for the AD Header
        self.AEADs = {}       # AEAD schemes used to decrypt ciphertexts

        # Keeps track of data necessary for decryption.
        self.keys = {}
        self.nonceDec = {}    # History of nonces for decryption

        # ADs associated to a label, dictionary mapping labels to dictionaries mapping
        # hashes to sets of ADs
        self.labelADs = {}

        # Used to map to 1 AD per label if 1AD option is true in scheme
        self.labelTo1AD = {}

        # ADs associated across sessions, dictionary mapping hashes to sets of ADs
        self.defaultADs = {}

        # Keeps track of which labels are currently in use.
        self.labels = set()

# Baseline aAE scheme using AES for the header and AES GCM for the AEAD scheme.
class aAEBase(aAEScheme):

    # Initializes the baseline scheme with information regarding the
    # details of the algorithms that it will use
    # TODO: Need to do some checks on ADKeyLen and oneAD
    def __init__(self, nonceKeyLen=32, ADKeyLen=0, aeadKeyLen=32, policy=None,
                 redundancy='\x00\x00\x00\x00', nonceLen=12, ADHdrLen=0, oneAD=True,
                 simpleStart=True, verbose=False):
        self.nonceKeyLen = nonceKeyLen                          # key for nonce header
        self.ADKeyLen = ADKeyLen                                # key for ad header
        self.aeadKeyLen = aeadKeyLen                            # key for aead scheme

        if isinstance(policy, PolicyFunction):
            self.policy = policy                                # nonce policy
        else:
            self.policy = None                                  # policy permitting all nonces

        self.nonceLen = nonceLen                                # length of nonces for scheme
        self.redundancy = redundancy                            # redundant bytes used w nonce
        self.redLen = len(redundancy)                           # length of redundant bytes
        self.ADHdrLen = ADHdrLen                                # length of AD Hdr
        self.nonceHdrLen = self.nonceLen + self.redLen          # will be length of input into BC
        self.verbose = verbose                                  # debug messages

        self.oneAD = oneAD                                      # If true, we can omit AD hdr
        if self.oneAD:
            self.ADHdrLen = 0
        self.simpleStart = simpleStart                          # If we allow dec to start non rand

        self.backend = default_backend()                        # used to instantiate primitives


    def initialize(self, key, state):
        label = state.lblCtr
        state.lblCtr += 1
        state.keys[label] = key

        # Parse key to set up primitives
        nonceKey = key[:self.nonceKeyLen]

        if not self.oneAD:
            ADKey = key[self.nonceKeyLen:self.nonceKeyLen+self.ADKeyLen]
            aeKey = key[-self.aeadKeyLen:]
        else:
            aeKey = key[self.nonceKeyLen:]

        # ECB mode to encode the nonce <= block size
        # Instead of the keys, we keep the track of the primitives initialized with the keys
        # Instantiate the encryptors and decryptors here so they don't need to
        # be instantiated later, this should speed things up significantly
        state.nonceBCs[label] = Cipher(algorithms.AES(nonceKey), modes.ECB(),
                self.backend).encryptor()
        state.nonceBCInvs[label] = Cipher(algorithms.AES(nonceKey), modes.ECB(),
                self.backend).decryptor()

        if not self.oneAD:
            state.ADBCs[label] = Cipher(algorithms.AES(ADKey), modes.ECB(),
                    self.backend).encryptor()
        state.AEADs[label] = AESGCM(aeKey)

        state.labels.add(label)
        state.nonceDec[label] = []
        state.labelADs[label] = {}
        return (label,state)


    def term(self, label, state):
        # The label must exist
        try:
            state.keys.pop(label)
            state.nonceBCs.pop(label)
            state.ADBCs.pop(label)
            state.AEADs.pop(label)
            if not self.oneAD:
                state.labelADs.pop(label)
            else:
                state.labelTo1AD.pop(label)
            state.nonceDec.pop(label)
            state.labels.remove(label)
        except KeyError:
            pass
        return state


    def asso(self, AD, state, label=None):
        if label not in state.labels and label is not None:
            return state

        # If there's only one AD ever
        if self.oneAD:
            if label is None:
                return state
            state.labelTo1AD[label] = AD
        else:
            # Hash the AD for a pointer to the AD
            hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
            hashFn.update(AD)
            hashedAD = hashFn.finalize()[:self.ADHdrLen]

            if label is None:
                state.defaultADs.setdefault(hashedAD,set()).add(AD)
            else:
                state.labelADs.setdefault(label,{}).setdefault(hashedAD,set()).add(AD)

        return state


    def disa(self, AD, state, label=None):
        if label not in state.labels and label is not None:
            return state

        # If there's only one AD ever
        if self.oneAD:
            if label is None:
                return state
            try:
                state.labelTo1AD[label].pop(AD)
            except KeyError:
                pass
        else:
            hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
            hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
            hashFn.update(AD)
            hashedAD = hashFn.finalize()[:self.ADHdrLen]

            if label is None:
                try:
                    state.defaultADs.setdefault(hashedAD,set()).remove(AD)
                except KeyError:
                    pass
            else:
                try:
                    state.labelADs.setdefault(hashedAD,{}).setdefault(hashedAD,set()).remove(AD)
                except KeyError:
                    pass
        return state


    def enc(self, key, nonce, AD, message):
        # Key parsing
        nonceKey = key[:self.nonceKeyLen]

        if not self.oneAD:
            ADKey = key[self.nonceKeyLen:self.nonceKeyLen+self.ADKeyLen]
            aeKey = key[-self.aeadKeyLen:]
        else:
            aeKey = key[self.nonceKeyLen:]

        # Generate nonce header
        nonceBC = Cipher(algorithms.AES(nonceKey), modes.ECB(), self.backend).encryptor()
        nonceHdr = nonceBC.update(nonce + self.redundancy)

        # Generate AD Header
        if not self.oneAD:
            ADBC = Cipher(algorithms.AES(ADKey), modes.ECB(), self.backend).encryptor()
            prfOut = prf(ADBC, self.ADHdrLen, nonce + self.redundancy)
            hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
            hashFn.update(AD)
            hashOut = hashFn.finalize()[:self.ADHdrLen]
            ADHdr = stringXor(prfOut,hashOut)
        else:
            ADHdr = ""

        aeEnc = AESGCM(aeKey)
        body = aeEnc.encrypt(nonce, message, AD)

        ctext = nonceHdr + ADHdr + body
        return ctext


    def dec(self, ciphertext, state):
        # Parse headers
        nonceHdr = ciphertext[:self.nonceHdrLen]
        ADHdr = ciphertext[self.nonceHdrLen:self.nonceHdrLen+self.ADHdrLen]
        body = ciphertext[self.nonceHdrLen+self.ADHdrLen:]

        # Decide starting point
        if not self.simpleStart:
            gen = SystemRandom()
            start = gen.randrange(state.lblCtr)
        else:
            start = 0

        # Iterate through each active label
        for i in range(start, start + state.lblCtr):
            label = i % state.lblCtr
            if label not in state.labels:
                continue

            # We don't need to parse the keys since we have primitives for each of them already

            # Extract the nonce from the ciphertext
            bcInv = state.nonceBCInvs[label]
            candidateNonce = bcInv.update(nonceHdr)
            if candidateNonce[-self.redLen:] != self.redundancy:
                continue
            nonce = candidateNonce[:self.nonceLen]

            # Check that nonce is within the policy
            # If no policy, accept all nonces
            if self.policy != None:
                if nonce not in self.policy.applyPolicy(state.nonceDec[label]):
                    continue

            if not self.oneAD:
                # Extract AD pointer from header
                prfOut = prf(state.ADBCs[label], self.ADHdrLen, nonce + self.redundancy)
                candidateHash = stringXor(prfOut, ADHdr)

                # Test each possible AD in decryption
                defaultADSet = state.defaultADs.setdefault(candidateHash,set())
                labelADSet = state.labelADs.setdefault(label,{}).setdefault(candidateHash,set())
                ADSet = labelADSet.union(defaultADSet)
            else:
                ADSet = set([state.labelTo1AD[label]])

            for AD in ADSet:
                try:
                    msg = state.AEADs[label].decrypt(nonce, body, AD)

                    # Update decryption history if we're using a policy
                    if self.policy != None:
                        state.nonceDec[label] = addToHistory(self.policy, nonce, state.nonceDec[label])
                    return (label, nonce, AD, msg, state)
                except (InvalidTag,InternalError):
                    continue
        return None

############################################################
# Dictionary-based scheme
############################################################
class DictState(object):

    def __init__(self):
        self.lblCtr = 0
        self.dict = {}        # Dictionary mapping nonce headers to contexts

        # Used in place of the key as the cipher and AEAD are instantiated using the key.
        self.nonceBCs = {}    # Block ciphers used in generating nonce header
        self.ADBCs = {}       # Block ciphers used in the prf for the AD Header
        self.AEADs = {}       # AEAD schemes used to decrypt ciphertexts

        self.nonceBCs = {}
        self.ADBCs = {}
        self.AEADs = {}

        self.keys = {}
        self.nonceDec = {}    # History of nonces for decryption

        # ADs associated to a label, dictionary mapping labels to dictionaries mapping
        # hashes to sets of ADs
        self.labelADs = {}

        # If there's only ever one AD, just do a simple mapping to that one AD
        self.labelTo1AD = {}

        # ADs associated across sessions, dictionary mapping hashes to sets of ADs
        self.defaultADs = {}

        self.nonceHdrs = {}

        self.labels = set()

class aAEDict(aAEScheme):

    # TODO: Need to do some checks on ADKeyLen and oneAD
    def __init__(self, nonceKeyLen=32, ADKeyLen=0, aeadKeyLen=32, policy=None,
            strict=True, oneAD=True, nonceLen=16, nonceHdrLen=8, ADHdrLen=8, verbose=False):
        self.nonceKeyLen = nonceKeyLen
        self.ADKeyLen = ADKeyLen
        self.aeadKeyLen = aeadKeyLen

        if isinstance(policy, PolicyFunction):
            self.policy = policy                     # nonce policy
        else:
            self.policy = SimplePolicy(nonceLength=nonceLen)

        self.nonceLen = nonceLen
        self.nonceHdrLen = nonceHdrLen
        self.ADHdrLen = ADHdrLen
        self.verbose = verbose

        self.oneAD = oneAD
        if self.oneAD:
            self.ADHdrLen = 0

        # If true, just do a strictly increasing nonce policy, ignoring the policy function
        # Also, state.nonceDec is not necessary if we know the policy is strict
        self.strict = strict


        self.backend = default_backend()

    def initialize(self, key, state):
        label = state.lblCtr
        state.lblCtr += 1
        state.keys[label] = key

        # Parse key to set up primitives
        nonceKey = key[:self.nonceKeyLen]
        if not self.oneAD:
            ADKey = key[self.nonceKeyLen:self.nonceKeyLen+self.ADKeyLen]
            aeKey = key[-self.aeadKeyLen:]
        else:
            aeKey = key[self.nonceKeyLen:]

        # ECB mode since we're only ever enciphering one block with these block ciphers
        state.nonceBCs[label] = Cipher(algorithms.AES(nonceKey), modes.ECB(),
                self.backend).encryptor()
        if not self.oneAD:
            state.ADBCs[label] = Cipher(algorithms.AES(ADKey), modes.ECB(),
                    self.backend).encryptor()
        state.AEADs[label] = AESGCM(aeKey)

        state.labels.add(label)
        state.nonceDec[label] = []
        state.labelADs[label] = {}

        for nonce in self.policy.applyPolicy(state.nonceDec[label]):
            nonceHdr = prf(state.nonceBCs[label], self.nonceHdrLen, nonce)
            state.dict.setdefault(nonceHdr,set()).add((label,nonce))
            state.nonceHdrs.setdefault(label,set()).add(nonceHdr)
        return (label, state)

    def term(self, label, state):
        for hdr in state.nonceHdrs[label]:
            for (candLabel, nonce) in state.dict[hdr].copy():
                if candLabel == label:
                    state.dict[hdr].remove((candLabel, nonce))

        if not self.oneAD:
            state.labelADs.pop(label)
        else:
            state.labelTo1AD.pop(label)
        state.nonceDec.pop(label)
        state.keys.pop(label)
        state.AEADs.pop(label)
        state.labels.remove(label)
        return state


    def asso(self, AD, state, label=None):
        if label not in state.labels and label is not None:
            return state

        if self.oneAD:
            if label is None:
                return state
            state.labelTo1AD[label] = AD
        else:
            # Hash the AD for a pointer to the AD
            hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
            hashFn.update(AD)
            hashedAD = hashFn.finalize()[:self.ADHdrLen]

            if label is None:
                state.defaultADs.setdefault(hashedAD,set()).add(AD)
            else:
                state.labelADs.setdefault(label,{}).setdefault(hashedAD,set()).add(AD)

        return state


    def disa(self, AD, state, label=None):
        if label not in state.labels and label is not None:
            return state

        if self.oneAD:
            if label is None:
                return state
            try:
                state.labelTo1AD[label].pop(AD)
            except KeyError:
                pass
        else:
            hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
            hashFn.update(AD)
            hashedAD = hashFn.finalize()[:self.ADHdrLen]

            if label is None:
                try:
                    state.defaultADs.setdefault(hashedAD,set()).remove(AD)
                except KeyError:
                    pass
            else:
                try:
                    state.labelADs.setdefault(label,{}).setdefault(hashedAD,set()).remove(AD)
                except KeyError:
                    pass
        return state


    def enc(self, key, nonce, AD, message):
        # Key parsing
        nonceKey = key[:self.nonceKeyLen]

        if not self.oneAD:
            ADKey = key[self.nonceKeyLen:self.nonceKeyLen+self.ADKeyLen]
            aeKey = key[-self.aeadKeyLen:]
        else:
            aeKey = key[self.nonceKeyLen:]

        # Generate nonce header
        nonceBC = Cipher(algorithms.AES(nonceKey), modes.ECB(), self.backend).encryptor()
        nonceHdr = prf(nonceBC, self.nonceHdrLen, nonce)

        if not self.oneAD:
            # Generate AD Header
            ADBC = Cipher(algorithms.AES(ADKey), modes.ECB(), self.backend).encryptor()
            prfOut = prf(ADBC, self.ADHdrLen, nonce)
            hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
            hashFn.update(AD)
            hashOut = hashFn.finalize()[:self.ADHdrLen]
            ADHdr = stringXor(prfOut,hashOut)
        else:
            ADHdr = ""

        aeEnc = AESGCM(aeKey)
        body = aeEnc.encrypt(nonce, message, AD)

        ctext = nonceHdr + ADHdr + body
        return ctext


    def dec(self, ciphertext, state):
        nonceHdr = ciphertext[:self.nonceHdrLen]
        ADHdr = ciphertext[self.nonceHdrLen:self.nonceHdrLen+self.ADHdrLen]
        body = ciphertext[self.nonceHdrLen+self.ADHdrLen:]

        LNset = state.dict.setdefault(nonceHdr,set())

        if LNset == set():
            print "Hdr not found: " + hexstring(nonceHdr)
            return None

        msg = None
        for (label, nonce) in LNset:

            # We don't need to parse the keys since we have primitives for each of them already

            if not self.oneAD:
                # Extract AD pointer from header
                prfOut = prf(state.ADBCs[label], self.ADHdrLen, nonce)
                candidateHash = stringXor(prfOut, ADHdr)

                # Test each possible AD in decryption
                defaultADSet = state.defaultADs.setdefault(candidateHash,set())
                labelADSet = state.labelADs.setdefault(label,{}).setdefault(candidateHash,set())
                ADSet = labelADSet.union(defaultADSet)
            else:
                ADSet = set([state.labelTo1AD[label]])

            for AD in ADSet:
                try:
                    msg = state.AEADs[label].decrypt(nonce, body, AD)

                    # We found a valid decryption
                    if msg is not None:
                        break

                except (InvalidTag,InternalError):
                    continue

            # We found a valid decryption, stop trial decryption
            if msg is not None:
                break

        # If no valid message was found under this header, return invalid
        if msg is None:
            return None

        # If we're using a general policy, we have to figure out which headers to add/remove
        if not self.strict:
            # Need to update the dictionary based on new expected headers
            oldNonces = self.policy.applyPolicy(state.nonceDec[label])
            state.nonceDec[label] = addToHistory(self.policy, nonce, state.nonceDec[label])
            newNonces = self.policy.applyPolicy(state.nonceDec[label])

            # Removing headers that are no longer valid in the future
            for rem in oldNonces.difference(newNonces):
                oldHdr = prf(state.nonceBCs[label], self.nonceHdrLen, rem)
                state.dict[oldHdr].remove((label,rem))
                state.nonceHdrs[label].remove(oldHdr)

            # Adding headers that will be valid later
            for add in newNonces.difference(oldNonces):
                newHdr = prf(state.nonceBCs[label], self.nonceHdrLen, add)
                state.dict.setdefault(newHdr,set()).add((label,add))
                state.nonceHdrs[label].add(newHdr)
        else:
            # We already know we're removing the received nonce and we actually don't
            # need to keep track of history if we're using strict
            state.dict[nonceHdr].remove((label,nonce))
            newNonce = nonceInc(nonce)
            newHdr = prf(state.nonceBCs[label], self.nonceHdrLen, newNonce)
            state.dict.setdefault(newHdr,set()).add((label,newNonce))
            state.nonceHdrs[label].add(newHdr)


        return (label, nonce, AD, msg, state)

##################################################################
# NonceWrap
##################################################################

class NonceWrapState(object):

    def __init__(self):

        # Counter for creating unique labels on reg() calls.
        self.lblCtr = 0
        self.LNA = {}         # Dictionary mapping nonce headers to contexts
        self.lblHdrs = {}   # Dictionary mapping labels to headers

        # Used in place of the key as the cipher and AEAD are instantiated using the key.
        self.nonceBCs = {}    # Block ciphers used in generating nonce header
        self.nonceBCInvs = {} # The inverses of the block ciphers (storing this should save time)
        self.AEADs = {}       # AEAD schemes used to decrypt ciphertexts

        # Keeps track of data necessary for decryption.
        self.keys = {}
        self.nonceDec = {}    # History of nonces for decryption

        # ADs associated to a label, dictionary mapping labels to dictionaries mapping
        # hashes to sets of ADs
        self.labelADs = {}

        # Used to map to 1 AD per label if 1AD option is true in scheme
        self.labelTo1AD = {}

        # ADs associated across sessions, dictionary mapping hashes to sets of ADs
        self.defaultADs = {}

        # Keeps track of which labels are currently in use.
        self.labels = set()


# Bookkeeping not in place to support more than 1AD/Key at the moment
class NonceWrap(aAEScheme):

    # Initializes the NonceWrap scheme with information regarding the
    # details of the algorithms that it will use
    def __init__(self, nonceKeyLen=32, aeadKeyLen=32, nx=None, lx=None,
                 redLen=4, ADHashLen=0, nonceLen=12, oneAD=True,
                 sharp=True):
        self.nonceKeyLen = nonceKeyLen                          # key for nonce header
        self.aeadKeyLen = aeadKeyLen                            # key for aead scheme

        if isinstance(nx, PolicyFunction):
            self.nx = nx                                        # nonce policy
        else:
            self.nx = None                                      # policy permitting all nonces

        if isinstance(lx, PolicyFunction):
            self.lx = lx                                        # nonce anticipation function
        else:
            self.lx = SimplePolicy(nonceLen)                    # anticipates next nonce

        self.sharp = sharp                                      # If true, header may be truncated
        self.oneAD = oneAD                                      # If true, we can omit AD hash
        self.nonceLen = nonceLen                                # length of nonces for scheme
        self.redLen = redLen
        self.redundancy = '\x00'*redLen                         # redundant bytes used w nonce
        if self.oneAD:
            self.ADHashLen = 0
        else:
            self.ADHashLen = ADHashLen                              # length of AD Hash
        self.hdrLen = self.nonceLen + self.redLen + self.ADHashLen    # will be length of input into BC

        self.backend = default_backend()                        # used to instantiate primitives


    def initialize(self, key, state):
        label = state.lblCtr
        state.lblCtr += 1
        state.keys[label] = key

        # Parse key to set up primitives
        nonceKey = key[:self.nonceKeyLen]
        aeKey = key[self.nonceKeyLen:]

        # ECB mode to encode the nonce <= block size
        # Instead of the keys, we keep the track of the primitives initialized with the keys
        # Instantiate the encryptors and decryptors here so they don't need to
        # be instantiated later, this should speed things up significantly
        state.nonceBCs[label] = Cipher(algorithms.AES(nonceKey), modes.ECB(),
                self.backend).encryptor()
        state.nonceBCInvs[label] = Cipher(algorithms.AES(nonceKey), modes.ECB(),
                self.backend).decryptor()

        state.AEADs[label] = AESGCM(aeKey)

        state.labels.add(label)
        state.nonceDec[label] = []
        state.labelADs[label] = {}

        for nonce in self.lx.applyPolicy([]):
            if not self.oneAD:
                for AD in state.defaultADs.values():
                    hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
                    hashFn.update(AD)
                    hashedAD = hashFn.finalize()[:self.ADHashLen]
                    head = nonce + self.redundancy + hashedAD
                    header = state.nonceBCs[label].update(head)
                    state.LNA.setdefault(header,set()).add((label,nonce,AD))
            else:
                head = nonce + self.redundancy
                header = state.nonceBCs[label].update(head)

                # If it's 1AD/key we don't need to store the AD
                state.LNA.setdefault(header,set()).add((label,nonce,state.""))
                state.lblHdrs.setdefault(label,set()).add(header)

        return (label,state)


    def term(self, label, state):
        # The label must exist
        if label not in state.labels:
            return state

        # Header removal
        for header in state.lblHdrs[label]:
            for (candLabel, nonce, AD) in state.LNA[header].copy():
                if candLabel == label:
                    state.dict[header].remove((candLabel, nonce, AD))

        try:
            state.keys.pop(label)
            state.nonceBCs.pop(label)
            state.AEADs.pop(label)
            if not self.oneAD:
                state.labelADs.pop(label)
            else:
                state.labelTo1AD.pop(label)
            state.nonceDec.pop(label)
            state.labels.remove(label)
        except KeyError:
            pass
        return state


    def asso(self, AD, state, label=None):
        if label not in state.labels and label is not None:
            return state

        # If there's only one AD ever
        if self.oneAD:
            if label is None:
                return state
            state.labelTo1AD[label] = AD
        else:
            # Hash the AD for a pointer to the AD
            hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
            hashFn.update(AD)
            hashedAD = hashFn.finalize()[:self.ADHashLen]

            if label is None:
                state.defaultADs.setdefault(hashedAD,set()).add(AD)
            else:
                state.labelADs.setdefault(label,{}).setdefault(hashedAD,set()).add(AD)

        return state


    def disa(self, AD, state, label=None):
        if label not in state.labels and label is not None:
            return state

        # If there's only one AD ever
        if self.oneAD:
            if label is None:
                return state
            try:
                state.labelTo1AD[label].pop(AD)
            except KeyError:
                pass
        else:
            hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
            hashFn.update(AD)
            hashedAD = hashFn.finalize()[:self.ADHdrLen]

            if label is None:
                try:
                    state.defaultADs.setdefault(hashedAD,set()).remove(AD)
                except KeyError:
                    pass
            else:
                try:
                    state.labelADs.setdefault(hashedAD,{}).setdefault(hashedAD,set()).remove(AD)
                except KeyError:
                    pass
        return state


    def enc(self, key, nonce, AD, message):
        # Key parsing
        nonceKey = key[:self.nonceKeyLen]
        aeKey = key[self.nonceKeyLen:]

        # Generate header
        nonceBC = Cipher(algorithms.AES(nonceKey), modes.ECB(), self.backend).encryptor()
        if self.oneAD:
            hashFn = hashes.Hash(hashes.SHA256(), backend=self.backend)
            hashFn.update(AD)
            hashedAD = hashFn.finalize()[:self.ADHashLen]
        else:
            hashedAD = ""

        header = nonceBC.update(nonce + self.redundancy + hashedAD)

        aeEnc = AESGCM(aeKey)
        body = aeEnc.encrypt(nonce, message, AD)

        ctext = header + body
        return ctext


    def dec(self, ciphertext, state):
        # Parse headers
        header = ciphertext[:self.hdrLen]
        body = ciphertext[self.hdrLen:]


        # Phase-2, iterates through label to search for tuple
        for label in state.labels:

            # We don't need to parse the keys since we have primitives for each of them already

            # Extract the nonce from the ciphertext
            bcInv = state.nonceBCInvs[label]
            hd = bcInv.update(header)
            nonce = hd[:self.nonceLen]
            red = hd[self.nonceLen : self.nonceLen + self.redLen]
            ADHash = hd[self.nonceLen + self.redLen:]

            # Check that the redundancy is present
            if red != self.redundancy:
                continue

            # Check that nonce is within the policy
            # If no policy, accept all nonces
            if self.nx != None:
                if nonce not in self.nx.applyPolicy(state.nonceDec[label]):
                    continue

            # Decide what ADs to try
            if not self.oneAD:
                # Test each possible AD in decryption
                defaultADSet = state.defaultADs.setdefault(ADHash,set())
                labelADSet = state.labelADs.setdefault(label,{}).setdefault(ADHash,set())
                ADSet = labelADSet.union(defaultADSet)
            else:
                ADSet = set([state.labelTo1AD[label]])

            for AD in ADSet:
                try:
                    msg = state.AEADs[label].decrypt(nonce, body, AD)

                    # Update decryption history if we're using a policy
                    if self.nx != None:
                        state.nonceDec[label] = addToHistory(self.nx, nonce, state.nonceDec[label])
                    return (label, nonce, AD, msg, state)
                except (InvalidTag,InternalError):
                    continue
        return None


