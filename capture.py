#!/usr/bin/python

import struct
import socket

def get_mac_addr(bytes_addr):
	#print(bytes_addr)
	bytes_str = map("{:02x}".format, bytes_addr)
	return ':'.join(bytes_str).upper()

#Ethernet frame
def parse_frame(frame):
	eth_len = 14
	eth_header = frame[:eth_len]
	eth_data = frame[eth_len:]
	dest_mac,src_mac,proto_field = struct.unpack('!6s6s2s' , eth_header)	
	dest_mac = get_mac_addr(dest_mac)
	src_mac = get_mac_addr(src_mac)
	# proto is of the form b'\x08\x00'
	proto = ''.join(map(str,proto_field))
	if proto == '80':
		ip_proto = 'IPV4'
	else:
		ip_proto = proto 
	print('\n\n*********Ethernet Frame*********')
	print("Source_MAC:",src_mac,"\tDestination_MAC:",dest_mac,"\nInternet Protocol:",ip_proto)
	return eth_data


def parse_packet(packet):
	#Contains IP version and Header Length
	first_byte = packet[0]

	#First 4 bits is version
	ip_version = first_byte >> 4
	#Next 4 bits is header_length
	ip_header_length = (first_byte & 15) * 4

	ttl,proto,src,dest = struct.unpack('!8xBB2x4s4s',packet[:20])

	#Ip address in string format..
	src_ip = get_ipv4(src)
	dest_ip = get_ipv4(dest)

	#Reverse dns lookup..
	src_web = rev_dnslookup(src_ip)
	dest_web = rev_dnslookup(dest_ip)

	if proto == 1:
		transport_proto = 'ICMP'
	elif proto == 6:
		transport_proto = 'TCP'
	elif proto == 17:
		transport_proto = 'UDP'
	else:
		transport_proto = 'Unknown Protocol Field = '+str(proto)

	print('---------IP Packet---------')
	print("Source_IP:",src_ip,"\tDestination_IP:",dest_ip,"\nTTL:",ttl,'hops\t','\tTransport_Protocol:',transport_proto)
	return packet[ip_header_length:]

def get_ipv4(addr):
	return '.'.join(map(str,addr))

#ip_addr is a string of type: '216.58.199.131'
def rev_dnslookup(ip_addr):
	#Ignore if a private Ip
	#Use an api/send request using requests module to fetch the domain name/website name
	#return domain name as a string or 'private_ip' if a private ip
	pass


#*******Main************

#Make the socket connection
conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3))

while True:
	#Receive the ethernet frame
	payload,addr = conn.recvfrom(65535)
	ip_packet = parse_frame(payload)
	ip_data = parse_packet(ip_packet)

