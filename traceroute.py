#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os,sys,time,subprocess
# import warnings,longging
# warnings.filterwarnings("ignore",category=DeprecationWarning)
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import traceroute

domains = raw_input('Please Input One OR More IP/Domain: ')
target = domains.split(' ')
dport = [80]

if len(target) >= 1 and target[0] != ' ':
	res,unans = traceroute(target,dport=dport,retry=-2)
	res.graph(target="> traceroute.svg")
	time.sleep(1)
	subprocess.Popen("/usr/bin/convert traceroute.svg traceroute.png", shell=True)
	print "IP/Domain Number OF Errors,Exit."
