#!/usr/bin/env python

import sys
from hashlib import sha1

def usage():
    print "Usage: {} <bignum len> <number>".format(sys.argv[0])
    exit()

if len(sys.argv) != 3:
    usage()
bignum_len = 0
try:
    bignum_len = int(sys.argv[1])
except:
    usage()

number = 0
try:
    numstr = sys.argv[2]
    if sys.argv[2][:2].lower() == '0x':
        base = 16
        numstr = numstr[2:]
    else:
        base = 10
    number = int(numstr, base)
except:
    usage()

def getsha1(data):
    return sha1(data).hexdigest()

def generate(bignum_len, number):
    numstr = str(number)
    if len(numstr) > bignum_len:
        return
    numstr = numstr.zfill(bignum_len)
    out = ""
    for i in xrange(4):
        for c in numstr:
            out += chr(ord(c) - ord('0'))

    out += chr(1) # operation
    out += chr(0) # opt
    with open("corpus/" + getsha1(out), 'wb') as fp:
        fp.write(out)
generate(bignum_len, number)
