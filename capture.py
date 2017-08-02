#!/usr/bin/python

import pcapy
import struct

def get_mac_addr(bytes_addr):
	#print(bytes_addr)
	bytes_str = map("{:02x}".format, bytes_addr)
	return ':'.join(bytes_str).upper()

def parse_packet(packet):
	eth_len = 14
	eth_header = packet[:eth_len]
	eth_data = packet[eth_len:]
	dest_mac,src_mac,proto = struct.unpack('!6s6s2s' , eth_header)	
	dest_mac = get_mac_addr(dest_mac)
	src_mac = get_mac_addr(src_mac)
	# proto is of the form b'\x08\x00'
	eth_proto = proto
	print('\n\n*********Ethernet Frame*********')
	print("\nSource:",src_mac,"Destination:",dest_mac,"\nProtocol:",eth_proto)
	print('Data : \n',eth_data)

devs = pcapy.findalldevs()
#print(devs)
lan = devs[0]
wlan = devs[1]


'''
open device
# Arguments here are:
#   device
#   snaplen (maximum number of bytes to capture _per_packet_)
#   promiscious mode (1 for true)
#   timeout (in milliseconds)
'''
cap = pcapy.open_live(wlan,65536,1,0)

count = 1

while count:
	(header,payload) = cap.next()
	parse_packet(payload)
	#print count,"\n", header,"\n"
	count+=1
