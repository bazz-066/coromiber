import threading
import time

from GramFrequency import GramFrequency
from Rules import Rules

class PacketMergerThread(threading.Thread):
	def __init__(self, packet_tuple, delay, n, rules, threshold):
		threading.Thread.__init__(self)
		self.done = False
		self.packet_tuple = packet_tuple
		self.message = ""
		self.delay = delay
		self.n = n
		self.rules = rules
		self.threshold = threshold

	def run(self):
		time.sleep(self.delay)
		self.done = True
		
		if len(self.message) > 0:
			ngram = GramFrequency(self.packet_tuple, self.message, self.n)
			print self.packet_tuple, self.message.encode('string_escape')#, ngram.list_frequency
			sims = self.rules.similarities(ngram.list_frequency)
			print sims
			
			alert = True

			for sim in sims:
				if sim < self.threshold:
					continue
				else:
					alert = False
					print self.packet_tuple, ": Benign"

			if alert == True:
				print self.packet_tuple, ": Intrusion !!!"

	def add_packet(self, data):
		if self.done:
			return
		elif len(data) < 0:
			self.done = True
			return;
		else:
			self.message = self.message + data
