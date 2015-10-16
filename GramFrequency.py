import sys

class GramFrequency(object):
	def __init__(self, packet_tuple, message, n):
		self.packet_tuple = packet_tuple
		self.message = message.decode('string_escape').lower()
		print self.message
		self.list_frequency = {}
		self.n = n
		self.genNGram()

	def genNGram(self):
		print len(self.message)
		for i in range(0, len(self.message)+1-self.n):
			substr = self.message[i:i+self.n]
			if self.list_frequency.get(substr) is not None:
				self.list_frequency[substr]+=1
			else:
				self.list_frequency[substr] = 1

#ngram = GramFrequency('1', 'aaaabbaabbb', int(sys.argv[1]))
#print ngram.packet_tuple, ngram.message, ngram.list_frequency
