import schemeTest

def runTest(verbose=False):
    schemeTest.schemeTest1(numUsers=10, schemeName="naive", rounds=3, verbose=verbose)

if __name__ == "__main__":
    runTest()
