import socket
from struct import *
import datetime
import pcapy
import sys
import hashlib
from impacket import ImpactDecoder, ImpactPacket
from threading import Lock

from Rules import Rules
from PacketMergerThread import PacketMergerThread
from GramFrequency import GramFrequency

rules = None
delay = 1000
capturedelay = 1000
threshold = 0.5
interface="eth0"
mode="capture"
infile="input.pcap"
outfile = "coromiber.rules"
n = 2
mutex = Lock()

count = 0

def main(argv):
	global rules
	global count

	try:
		conffile = argv[1].split("=")[1]
		if loadconfig(conffile) == -1:
			return -1

		print "main mode:" + mode
		if mode == "capture":
			cap = pcapy.open_live(interface, 65536, 1, capturedelay)
			cap.setfilter('ip proto \\tcp')
			rules = Rules()
		elif mode == "genrule":
			cap = pcapy.open_offline(infile)
			cap.setfilter('ip proto \\tcp')
		else:
			print "Unknown mode"
			quit()
		messages = {}
		flog = open("log.txt", "w")
	except IndexError as e:
		print "Usage : python coromiber.py conf=[coromiber.conf]"
		print e
		quit()
	while(1):
		try:
			(header, packet) = cap.next()
			if not header:
				break
			parse_packet(packet, messages, n, flog)
		except (TypeError, AttributeError, NameError) as e:
			print e
		except pcapy.PcapError:
			break
		except KeyboardInterrupt:
			print "CoroMiber is Shuttting Down ..."
			flog.close()
			quit()
		except socket.timeout:
			#continue
			print "Nothing come", sys.exc_info()[0]

	if mode == "genrule":
		genrule(messages)

def genrule(messages):
	frules = open(outfile, "w")

	for packet_tuple, pmt in messages.iteritems():
		ngram = GramFrequency(packet_tuple, pmt.message, n)
		for gram, freq in ngram.list_frequency.iteritems():
			if len(gram) > 0:
				frules.write(gram.encode('string_escape') + ":" + str(freq) + ";")
		frules.write("\n")

	frules.close()

def loadconfig(conffile):
	global delay
	global capturedelay
	global threshold
	global interface
	global mode
	global infile
	global outfile
	global n

	fconf = open(conffile, "r")
	count = 1

	for line in fconf.readlines():
		opts = line.strip().split("=")

		if len(opts) != 2:
			print conffile + " config file error at line " + str(count)
			return -1 
		elif opts[0] == "mode":
			mode = opts[1]
		elif opts[0] == "outfile":
			outfile = opts[1]
		elif opts[0] == "threshold":
			threshold = float(opts[1])
		elif opts[0] == "delay":
			delay = int(opts[1])
		elif opts[0] == "capturedelay":
			capturedelay = int(opts[1])
		elif opts[0] == "interface":
			interface = opts[1]
		elif opts[0] == "n":
			n = int(opts[1])

		count+=1

	fconf.close()
	print "mode : " + mode
	return 0
			
def parse_packet(packet, messages, n, flog):
	decoder = ImpactDecoder.EthDecoder()
	ether = decoder.decode(packet)

	iphdr = ether.child()
	tcphdr = iphdr.child()

	if not tcphdr.get_FIN() and not tcphdr.get_SYN():	
		s_addr = iphdr.get_ip_src()
		d_addr = iphdr.get_ip_dst()
		sport = tcphdr.get_th_sport()
		dport = tcphdr.get_th_dport()
		data = tcphdr.get_data_as_string()
	       
		if (dport == 80) and len(data) > 0:
			#print s_addr, d_addr, sport, dport
			#print "len : " + str(len(data))
			#print "data : " + data
			#print "Packet from ", s_addr, sport, dport
			h = hashlib.sha256()
			h.update(str(s_addr) + str(d_addr) + str(sport) + str(dport))
			packet_tuple = h.hexdigest()
			tcp_reconstruction(messages, data, packet_tuple, n, flog)

def tcp_reconstruction(messages, data, packet_tuple, n, flog):
	global count
	global rules	
	
	client = messages.get(packet_tuple)

	if not client:
		tmp = PacketMergerThread(packet_tuple, delay, n, rules, threshold, flog, mutex)
		tmp.add_packet(data)
		if mode == "capture":
			tmp.start()
		messages[packet_tuple] = tmp
		count += 1
		print count
	else:
		client.add_packet(data)

if __name__ == "__main__":
	main(sys.argv)
