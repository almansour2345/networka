import os

out = os.popen('ip neigh').read().splitlines()
print out
print (len(out))
for i, line in enumerate(out, start=1):
	ip = line.split(' ')[0]
	h = os.popen('host {}'.format(ip)).read()
	hostname = h.split(' ')[-1]
	cc=("{:>4}:  {}".format( hostname.strip(), ip))
	cd=cc
	xd=[]
	xd.append(cd)
# ~ for item in cd:
	# ~ r3 = cd
	# ~ print "\n\n\nthis is r3"

	# ~ xx=str(r3)
	# ~ print xx


# ~ print xd
print cc
ccd=str(out).strip('[]')
print ccd


