#!/usr/bin/env python

import pexpect
import sys
import argparse


parser = argparse.ArgumentParser(description="parameters")
parser.add_argument('--h', help='target host or IP' )
parser.add_argument('--u', help='username', nargs='?', const=1, default="" )
parser.add_argument('--p', help='password', nargs='?', const=1, default="" )
parser.add_argument('--cmd', help='command')
parser.add_argument('--quite', action='store_true', help='hide cli output')
args = parser.parse_args()


try:
    child = pexpect.spawn('ssh %s@%s' % (args.u, args.h))
    if not args.quite:
        child.logfile = sys.stdout
    child.timeout = 4
    child.expect('assword:')
except pexpect.TIMEOUT:
    raise OurException("Couldn't log on to the device")

child.sendline(args.p)
child.expect(['>', '#'])
if args.cmd:
    parse = args.cmd.split(';')
    for cmd in parse:
        child.sendline(cmd)
        child.expect(['>', '#'])
child.sendline('exit')
