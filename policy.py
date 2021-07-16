import struct
import utilities
import abc

MAXINT32 = 0xFFFFFFFF
MAXINT64 = 0xFFFFFFFFFFFFFFFF

class PolicyFunction(object):
    __metaclass = abc.ABCMeta

    # The domain of the policy
    # Histories should not exceed the size of the domain when submitted to this policy
    @abc.abstractproperty
    def domain(self):
        pass

    # History - a list of nonces that the policy is basing the next set of valid nonces on
    # Returns a set of nonces that are deemed valid based on this history.
    @abc.abstractmethod
    def applyPolicy(self, history):
        pass


# Assumes nonce is counter of some length in bytes
# Just expects the next nonce in the counter
class SimplePolicy(PolicyFunction):

    def __init__(self, nonceLength=12):
        self.nonceLength = nonceLength   # Size of the nonces
        self.domain = 1

    def domain(self):
        return self.domain

    def applyPolicy(self,history):
        if history == []:
            return set([utilities.intToNonce(self.nonceLength)])

        last = history[-1]
        return set([utilities.nonceInc(last)])

# Utility function where given a policy,
# we add nonce to the history.
def addToHistory(policy, nonce, history):
    history.append(nonce)
    if len(history) > policy.domain:
        history = history[1:]
    return history


def simplePolicyTest():
    nonce1 = struct.pack(">IQ", 0, 0)
    nonce2 = struct.pack(">IQ", 0, MAXINT64)
    nonce3 = struct.pack(">IQ", MAXINT32, MAXINT64)

    sp = SimplePolicy()
    nonces = []
    print sp.applyPolicy(nonces)
    nonces = [nonce1]
    print sp.applyPolicy(nonces)
    nonces = [nonce2]
    print sp.applyPolicy(nonces)
    nonces = [nonce3]
    print sp.applyPolicy(nonces)

