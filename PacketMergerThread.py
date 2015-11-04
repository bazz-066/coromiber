import threading
import time
from threading import Lock

from GramFrequency import GramFrequency
from Rules import Rules

class PacketMergerThread(threading.Thread):
	def __init__(self, packet_tuple, delay, n, rules, threshold, flog, mutex):
		threading.Thread.__init__(self)
		self.done = False
		self.packet_tuple = packet_tuple
		self.message = ""
		self.delay = delay
		self.n = n
		self.rules = rules
		self.threshold = threshold
		self.flog = flog
		self.mutex = mutex

	def run(self):
		time.sleep(self.delay)
		self.done = True
		
		if len(self.message) > 0:
			ngram = GramFrequency(self.packet_tuple, self.message, self.n)
			#print self.packet_tuple, self.message.encode('string_escape')#, ngram.list_frequency
			sims = self.rules.similarities(ngram.list_frequency)
			print sims
			
			alert = True

			for sim in sims:
				if sim < self.threshold:
					continue
				else:
					alert = False
					#print self.packet_tuple , ": Benign"

			if alert == True:
				self.mutex.acquire(1)
				print sims
				self.flog.write(str(self.packet_tuple) + ": Intrusion !!!\n")
				self.mutex.release()

	def add_packet(self, data):
		if self.done:
			return
		elif len(data) < 0:
			self.done = True
			return;
		else:
			self.message = self.message + data
