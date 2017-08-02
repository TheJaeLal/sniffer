#!/usr/bin/python

import pcapy
from struct import *

def get_mac_addr(bytes_addr):
	#print(bytes_addr)
	bytes_str = map("{:02x}".format, bytes_addr)
	return ':'.join(bytes_str).upper()

def parse_packet(packet):
	eth_len = 14
	dest_mac,src_mac,proto = unpack('! 6s 6s H' , packet[:eth_len])	
	dest_mac = get_mac_addr(dest_mac)
	src_mac = get_mac_addr(src_mac)
	eth_protocol = 
	print("\n\nDestination Mac:",dest_mac,"\nSource Mac:",src_mac,"\nProtocol:",proto)


devs = pcapy.findalldevs()
#print(devs)
lan = devs[0]
wlan = devs[1]

cap = pcapy.open_live(wlan,65536,1,0)

count = 1

while count:
	(header,payload) = cap.next()
	parse_packet(payload)
	#print count,"\n", header,"\n"
	count+=1
