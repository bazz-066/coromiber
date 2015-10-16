class Grams(object):
	def __init__(self, line_rule):
		self.rule = {}
		arr_grams = line_rule.split(";")
		for str_gram in arr_grams:
			arr_gram = str_gram.split(":");
			self.rule[arr_gram[0]] = int(arr_gram[1])

class Rules(object):
	def __init__(self, rules_file='coromiber.conf'):
		self.list_rules = {}
		index = 0
		frules = open(rules_file, 'r')
		for line_rule in frules:
			rule = Grams(line_rule.strip())
			self.list_rules[index] = rule
			index+=1

		frules.close()

rules = Rules()
for index in range(0, len(rules.list_rules)):
	print rules.list_rules[index].rule
