import socket
from struct import *
import datetime
import pcapy
import sys
import hashlib

from GramFrequency import GramFrequency

def main(argv):
	try:
		cap = pcapy.open_live(argv[1], 65536, 1, 10000)
		messages = {}
		n = int(argv[2])
	except IndexError:
		print "Usage : python coromiber.py <interface> <n-gram>"
		quit()

	while(1):
		try:
			(header, packet) = cap.next()
			parse_packet(packet, messages, n)
		except (TypeError, AttributeError, NameError) as e:
			print e
		except KeyboardInterrupt:
			print "CoroMiber is Shuttting Down ..."
			quit()
		except socket.timeout:
			#continue
			print "Nothing come", sys.exc_info()[0]


def parse_packet(packet, messages, n):
	eth_length = 14

	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH', eth_header)
	eth_protocol = socket.ntohs(eth[2])

	#print eth_protocol

	if eth_protocol == 8: #ETHERNET PACKET
		ip_header = packet[eth_length:20+eth_length]

		iph = unpack('!BBHHHBBH4s4s', ip_header)
		version = iph[0] >> 4
		ihl = iph[0] & 0xF

		ip_protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8])
		d_addr = socket.inet_ntoa(iph[9])
		#print ip_protocol
		if int(ip_protocol) == 6:
			t = (ihl * 4) + eth_length
			tcp_header = packet[t:t+20]

			tcph = unpack('!HHLLBBHHH', tcp_header)

			sport = tcph[0]
			dport = tcph[1]
			tcph_length = tcph[4] >> 4

			h_size = eth_length + (ihl * 4) + (tcph_length * 4)
			data = packet[h_size:]

			if (int(dport) == 80) and len(data) > 0:
				#print "new packet ", len(data)	
				print "Packet from ", s_addr, sport, dport
				h = hashlib.sha256()
				h.update(str(s_addr) + str(d_addr) + str(sport) + str(dport))
				packet_tuple = h.hexdigest()
				tcp_reconstruction(messages, data, packet_tuple)

def tcp_reconstruction(messages, data, packet_tuple):
	message = messages.get(packet_tuple)

	if not message:
		messages[packet_tuple] = data
	else:
		messages[packet_tuple] = messages[packet_tuple] + data

	ngram = GramFrequency(packet_tuple, messages[packet_tuple], int(sys.argv[2]))
	print ngram.list_frequency

if __name__ == "__main__":
	main(sys.argv)
