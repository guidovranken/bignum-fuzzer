import re

rgx = r'(\w+)\(([0-9, -]+)\) = ([0-9-]+)$'

for fn in ["tests_1200.txt", "tests_100.txt"]:
    with open(fn, "rb") as fp:
        for l in fp:
            l = l.strip()
            m = re.match(rgx, l)
            operation = m.group(1)
            numbers = [n.strip() for n in m.group(2).split(',')]
            result = m.group(3)

            if operation == "ADD":
                print "console.assert({})".format("+".join(["BigInt('{}')".format(n) for n in numbers]) + "==" + "BigInt('{}')".format(result))
            elif operation == "SUB":
                print "console.assert({})".format("-".join(["BigInt('{}')".format(n) for n in numbers]) + "==" + "BigInt('{}')".format(result))
            elif operation == "MUL":
                print "console.assert({})".format("*".join(["BigInt('{}')".format(n) for n in numbers]) + "==" + "BigInt('{}')".format(result))
            elif operation == "DIV":
                print "console.assert({})".format("/".join(["BigInt('{}')".format(n) for n in numbers]) + "==" + "BigInt('{}')".format(result))
            elif operation == "MOD":
                print "console.assert({})".format("%".join(["BigInt('{}')".format(n) for n in numbers]) + "==" + "BigInt('{}')".format(result))
            elif operation == "EXP":
                print "console.assert({})".format("**".join(["BigInt('{}')".format(n) for n in numbers]) + "==" + "BigInt('{}')".format(result))
            elif operation == "LSHIFT1":
                print "console.assert({})".format("<<".join(["BigInt('{}')".format(n) for n in (numbers + ['1'])]) + "==" + "BigInt('{}')".format(result))
            elif operation == "RSHIFT1":
                if '-' not in str(numbers):
                    print "console.assert({})".format(">>".join(["BigInt('{}')".format(n) for n in (numbers + ['1'])]) + "==" + "BigInt('{}')".format(result))
            elif operation == "SQR":
                print "console.assert({})".format("**".join(["BigInt('{}')".format(n) for n in (numbers + ['2'])]) + "==" + "BigInt('{}')".format(result))
            elif operation == "NEG":
                print "console.assert({})".format("-".join(["BigInt('{}')".format(n) for n in (['0'] + numbers)]) + "==" + "BigInt('{}')".format(result))
            elif operation == "ADD_MOD":
                if '-' not in str(numbers):
                    print "console.assert(({} + {}) % {} == {})".format(*["BigInt('{}')".format(n) for n in (numbers + [result])])
            elif operation == "MUL_MOD":
                if '-' not in str(numbers):
                    print "console.assert(({} * {}) % {} == {})".format(*["BigInt('{}')".format(n) for n in (numbers + [result])])
