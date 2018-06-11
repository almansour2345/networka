#!/usr/bin/python2.7 
import easygui as g
import sys
import commands
import os
import netifaces  
import time 
import datetime
import commands
import string
import random
#import re
from scapy.all import *
import signal
import threading
import os.path


### def to use arp-scan to grab all devices on network
## note arp-scan is a linux program must be installed on your system 

def arpere(xfac,xip):
	t = commands.getoutput("arp-scan --interface='%s'  '%s'" %  (xfac , xip ,)) 
	print t
	dd=commands.getoutput("date")
	cc= dd + "_"+ "_ARP_" +".txt"
	lx = open(cc, "ab+")
	lx.write(t)
	lx.close()
	return t




def pngg():
	ffe=os.path.isfile("dnss.txt")
	if ffe==True:
		f = open('dnss.txt')
		### compain the id with a date and time for the logging file 
		dd=commands.getoutput("date")
		cc= dd + "_" +".txt"
		
		for line in f:
			fields = line.strip().split()
			## storing ping in the var
			tp = ("ping -c 4 %s")% fields[1]
			## pingig it
			p = commands.getoutput(tp)
			## opening the logging file and start logging
			lo = open(cc, "ab+")
			jj = "\n\n\n\n\n ___XXXXXXXXXXXXXXXXXXXXXXXXXX___xxxx %s xxxx___XXXXXXXXXXXXXXXXXXXXXXXXXX___ \n" % fields[0]
			jr = "\n __Host = %s \n" % fields[0]
	#		print jj
	#		print "\n\t"	
			## uncomment if you want terminal display for the pings 
		#	print p 
	#		print "for \n\n"
	#		print(fields[1])
			## uncomment if you want to log the pings also 
			ers=dd + "\t\t" + jj  +  "\n\t" + str(p) + "for \n\n" + fields[1] + "\n\n ____ \n\n"
			## comment if you uncomment the previus line
		#	ers=dd + "\n" + jr +  "\n" + "ip: " + fields[1] + "\n____"
			pp1=str(p)
			t1r=pp1.find('time=')
			fp=pp1.find(' ',t1r)
			tl1=pp1[t1r+1:fp]
			spe='t'+tl1
			px= "\tSpeed \n\tPing_t" + str(spe) + "\n\n ____ \n\n"
	#		print px
			## logging now 	
			ersd=ers
			lo.write(ersd)	
			lo.write(px)
			g.msgbox(px)
	 
	else:
		f=open("dnss.txt","ab+")
		tt="8.8.8.8\t\tGOOGLE1\n8.8.4.4\t\tGOOGLE2"
		f.write(tt)
		f.close()
		f = open('dnss.txt')
		### compain the id with a date and time for the logging file 
		dd=commands.getoutput("date")
		cc= dd + "_" +".txt"
		
		for line in f:
			fields = line.strip().split()
			## storing ping in the var
			tp = ("ping -c 4 %s")% fields[1]
			## pingig it
			p = commands.getoutput(tp)
			## opening the logging file and start logging
			lo = open(cc, "ab+")
			jj = "\n\n\n\n\n ___XXXXXXXXXXXXXXXXXXXXXXXXXX___xxxx %s xxxx___XXXXXXXXXXXXXXXXXXXXXXXXXX___ \n" % fields[0]
			jr = "\n __Host = %s \n" % fields[0]
	#		print jj
	#		print "\n\t"	
			## uncomment if you want terminal display for the pings 
		#	print p 
	#		print "for \n\n"
	#		print(fields[1])
			## uncomment if you want to log the pings also 
			ers=dd + "\t\t" + jj  +  "\n\t" + str(p) + "for \n\n" + fields[1] + "\n\n ____ \n\n"
			## comment if you uncomment the previus line
		#	ers=dd + "\n" + jr +  "\n" + "ip: " + fields[1] + "\n____"
			pp1=str(p)
			t1r=pp1.find('time=')
			fp=pp1.find(' ',t1r)
			tl1=pp1[t1r+1:fp]
			spe='t'+tl1
			px= "\tSpeed \n\tPing_t" + str(spe) + "\n\n ____ \n\n"
	#		print px
			## logging now 	
			ersd=ers
			lo.write(ersd)	
			lo.write(px)
			g.msgbox(px)
	 
##def to set a linux system for sniffing

def ssetiupfor():
	tse0 = commands.getoutput("cp  /etc/sysctl.conf   /etc/sysctl.conf.backup ")
	tse1 = commands.getoutput("echo  \'net.inet.ip.forwarding=1\' >> /etc/sysctl.conf ")
	tse2 = commands.getoutput("sysctl -p")
	tse3 = commands.getoutput("echo 1 > /proc/sys/net/ipv4/ip_forward") 
	tse4 = commands.getoutput("ifconfig %s promisc " % (xfac)) 
	tse5 = commands.getoutput("iptables-save | sudo tee /etc/iptables/iptables55.rules")
	tse6 = commands.getoutput("iptables -t nat -A POSTROUTING --out-interface %s  -j MASQUERADE   " % (xfac )) 
	tse7 = commands.getoutput("sudo iptables -A FORWARD --in-interface  %s  -j ACCEPT " % (xfac)) 




##def to unseting a linux system for sniffing

def unssetiupfor():
	tsu0 = commands.getoutput("cp  /etc/sysctl.conf.backup   /etc/sysctl.conf ; rm /etc/sysctl.conf.backup")
	tsu1 = commands.getoutput("sysctl -w net.inet.ip.forwarding=0")
	tsu2 = commands.getoutput("sysctl -p")
	tsu3 = commands.getoutput("echo 0 > /proc/sys/net/ipv4/ip_forward") 
	tsu4 = commands.getoutput("ifconfig %s -promisc " % (xfac)) 
	tse5 = commands.getoutput("isudo iptables-restore < /etc/iptables/iptables55.rules") 
	tse6 = commands.getoutput("iptables -D FORWARD --in-interface  %s  -j ACCEPT " % (xfac)) 


##starting here 
g.msgbox("Hello, this is a program for network admins!")
while 1:

	msg ="Please choose your interface ,then choose your network   " 
	title = "Starting up!"
	##getting interfaces useing netifaces module and removeing lo interface 
	
	xx=netifaces.interfaces()
	xx.remove("lo")
	choices = xx
	choice = g.choicebox(msg, title, choices)
	xn= str(choice)
	
	if xn !="None":
				
		## get the ip of the interface 
		tp = ("ip add show %s | grep inet ") % xn
		p = commands.getoutput(tp)
		fields = p.strip().split()	
		xrp= fields[1]
		xip = str(xrp)
		tt2=xip.find('/24')
		tr=xip[0:tt2]
		print tr
		print xip
	
		## get the mac of your device 
		tp2 = ("ip add show %s | grep link/ether ") % xn
		p2 = commands.getoutput(tp2)
		fields2 = p2.strip().split()
		xrp2 = fields2[1]
		xmac=str(xrp2)
		print xmac
		
		## get the main router #router ip 
		tp3 = ("route | grep default ")
		p3 = commands.getoutput(tp3)
		fields3 = p3.strip().split()
		xrp3 = fields3[1]
		xrouterip=str(xrp3)
		print xrouterip
		
		
			
		xfac=str(xn)
		subx= re.split(r"(?<!^)\s*[.\n]+\s*(?!$)", xrp)
		supx= subx[3:4]
		
		while 1:
				
			msg ="Please choose what next !" 
			title = "S!"
			choices = ["check whois on network", "ping dns","set it up for sniffing  -_* ","remove sniffing setups","start spoffary"]
			choice = g.choicebox(msg, title, choices)
			x1= str(choice)
			if x1=="check whois on network":
				g.msgbox("You choose to check whois on network we will grap all network mac address and have it avilable in a txt file " )
				t=arpere(xfac,xip)
				
				g.msgbox(t)
			elif x1=="ping dns":
				g.msgbox("You will Find a ping result for dnss in a txt file  ")
				pngg()
				
			elif x1=="set it up for sniffing  -_* ":
				g.msgbox("you are ready to start sniffing now" )
				ssetiupfor()
				
			elif x1=="remove sniffing setups":
				g.msgbox("set up reseted to orignal   ")
				unssetiupfor()
				
			elif x1=="start spoffary":
				g.msgbox("spoffing arps starting now")
				#ARP poison thread
				poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
				poison_thread.start()
				arsp()
			# note that we convert choice to string, in case
			# the user cancelled the choice, and we got None.
			xr=str(choice)
			if xr !="None":
				g.msgbox("You chose: " + str(choice))
				msg = "Do you want to continue?"
				title = "Please Confirm"
				
			# show a Continue/Cancel dialog
				pass # user chose Continue
			else:
				sys.exit(0)
	 

	else:
		sys.exit()
	
	
	
	if g.ccbox(msg, title):
	# show a Continue/Cancel dialog
		pass # user chose Continue
	else:
		sys.exit(0)	
