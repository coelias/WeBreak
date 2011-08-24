import re

class data:
	pass
	
class Number(data):
	@staticmethod
	def input(default=None,cad="Enter a number"):
		if default:
			cad +=" [{0}]: ".format(default)
		else:
			cad+=": "
		a=raw_input(cad)
		try:
			return int(a)
		except:
			if default:
				return default
			raise Exception("Incorrect value")

class String(data):
	@staticmethod
	def input(default,cad="Enter a string"):
		if default:
			cad +=" [{0}]: ".format(default)
		else:
			cad+=": "
		a=raw_input(cad)
		if not a.strip() and default:
			return default
		return a.replace("\r","").replace("\n","")

class Option(data):
	@staticmethod
	def input(options,cad="Select an option"):
		opts,default=options
		if default not in opts:
			raise Exception("Default not in options")
		if default:
			cad+=" [{0}]: ".format(opts.index(default)+1)
		else:
			cad+=": "

		for i in enumerate(opts,1):
			print ("{0}: {1}".format(i[0],i[1]))
		a=raw_input(cad)
		try:
			a=int(a)
			if a not in range(1,len(opts)+1):
				raise Exception()
			return opts[a-1]
		except:
			if default:
				return default
			raise Exception("Wrong option")

class ListString(data):
	@staticmethod
	def input(par,cad="Enter a list of strings (end with empty string) :"):
		print cad
		lst=[]
		a=raw_input().strip()
		while a:
			lst.append(a)
			a=raw_input().strip()
		return lst


