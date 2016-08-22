#!/usr/bin/env python2
#
# gen_mac_prefixes.py - This file will generate the mac-prefixes file from ieee.org OUI file.
#
# Written by Hypsurus <hypsurus@mail.ru>
# (22/07/2016)
# 

import sys
import os
from subprocess import Popen as p

FILE="http://standards-oui.ieee.org/oui.txt"

def get_db():
	print("[*] Downloading ${OUI} ...")
	p("curl -O -L %s" % (FILE), shell=True).wait()
		
def parse_db():
	if os.path.abspath("./").split("/")[-1] != "tools":
		print("[*] Please run this script from the \'tools/\' folder.")
		sys.exit()

	if not os.path.exists("./oui.txt"):
		get_db()

	counter = 0
	out_file = open("../txt/mac-prefixes", "w")

	with open("oui.txt", "r") as db:
		for line in db.readlines():
			line = line.replace("\n", "")
			if "base 16" in line:
				line = line.replace("(base 16)", "")
				line = line.replace("     		", " ")
				out_file.write("%s\n" %line)
				counter+=1

	print("[*] %d lines written to ../txt/oui.txt" %counter)
	out_file.close()
	os.remove("out.txt")

def main():
	parse_db()

if __name__ == '__main__':
	main()

