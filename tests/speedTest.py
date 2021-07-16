import schemeTest
import sys

if __name__=="__main__":
    if len(sys.argv) != 6:
        print "Usage: python speedTest.py [nae, base, dict, naive] [number of keys] [message size in bytes] [number of inner rounds] [number of outer rounds]"
        exit()

    rounds = int(sys.argv[5])
    times = []

    for i in range(rounds):
        if sys.argv[1] == "nae":
            times.append(schemeTest.naeSpeedTest(msgSize=int(sys.argv[3]),
                rounds=int(sys.argv[4])))
        elif sys.argv[1] == "naive":
            times.append(schemeTest.schemeSpeedTest(numUsers=int(sys.argv[2]),
                msgSize=int(sys.argv[3]), schemeName="naive", rounds=int(sys.argv[4])))
        elif sys.argv[1] == "base":
            times.append(schemeTest.schemeSpeedTest(numUsers=int(sys.argv[2]),
                msgSize=int(sys.argv[3]), schemeName="base", rounds=int(sys.argv[4])))
        elif sys.argv[1] == "dict":
            times.append(schemeTest.schemeSpeedTest(numUsers=int(sys.argv[2]),
                msgSize=int(sys.argv[3]), schemeName="dict", rounds=int(sys.argv[4])))

    times.sort()
    cut = rounds/4
    y = times[cut:-cut]
    tot = 0.0

    for i in y:
        tot += i

    print "Average {}".format(tot/len(y))
    #print times
