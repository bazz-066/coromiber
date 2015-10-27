import math
import binascii

class Grams(object):
	def __init__(self, line_rule):
		self.rule = {}
		arr_grams = line_rule.split(";")
		for str_gram in arr_grams:
			if len(str_gram) > 0:
				arr_gram = str_gram.split(":");
				self.rule[binascii.unhexlify(arr_gram[0])] = int(arr_gram[1])

class Rules(object):
	def __init__(self, rules_file='coromiber.rules'):
		self.list_rules = {}
		index = 0
		frules = open(rules_file, 'r')
		for line_rule in frules:
			rule = Grams(line_rule.strip())
			self.list_rules[index] = rule
			index+=1

		frules.close()

	def cosine_sims(self, incoming_gram, gram_rule):
		up_sum = 0
		down_sum_a = 0
		down_sum_b = 0

		for key, a in incoming_gram.iteritems():
			b = 0 if gram_rule.rule.get(key) is None else gram_rule.rule.get(key)
			up_sum += a*b
			down_sum_a += math.pow(a,2)

		for key, b in gram_rule.rule.iteritems():
			down_sum_b += math.pow(b,2)

		return up_sum / (math.sqrt(down_sum_a) * math.sqrt(down_sum_b))

	def similarities(self, incoming_gram, algorithm='cosine'):
		sims = []
		for key, rule in self.list_rules.iteritems():
			if algorithm == 'cosine':
				sims.append(self.cosine_sims(incoming_gram, rule))

		return sims
		

#rules = Rules()
#inc = {'aa':1, 'bb':2, 'cc':3}
#sims = rules.similarities(inc)
#print sims
