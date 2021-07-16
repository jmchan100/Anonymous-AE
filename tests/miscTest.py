import schemeTest

def runTest(verbose=False):
    if verbose:
        print "----------------------------Disa test for base scheme----------------------------"
    schemeTest.schemeDisaTest(verbose=verbose)

    if verbose:
        print "----------------------------Disa test for dict scheme----------------------------"
    schemeTest.schemeDisaTest("dict",verbose=verbose)

    if verbose:
        print "----------------------------Term test for base scheme----------------------------"
    schemeTest.schemeTermTest(verbose=verbose)

    if verbose:
        print "----------------------------Term test for dict scheme----------------------------"
    schemeTest.schemeTermTest("dict",verbose=verbose)

if __name__ == "__main__":
    runTest()
