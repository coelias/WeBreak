import re
import datainput

class payload:
	def __init__(self):
		self.count=0
		self.appended=None
		self.actual=None

	def __iter__ (self):
		self.initialize()
		a=self.next()
		while a:
			yield a
			a=self.next()
		raise StopIteration

	def initialize(self):
		pass

	def __len__(self):
		if self.appended!=None:
			return self.count*len(self.appended)
		return self.count

	def append(self,payload):
		self.appended=payload
		self.appenditerator=self.appended.__iter__()

	def next (self):
		if self.appended!=None:
			try:
				if not self.actual:
					self.actual=self.do_next()
				return self.actual+self.appenditerator.next()
			except StopIteration:
				self.actual=self.do_next()
				self.appenditerator=self.appended.__iter__()
				return self.actual+self.appenditerator.next()
		else:
			return self.do_next()

	def do_next(self):
		raise StopIteration

class payload_iterator:
	pass


######## Inheritances

class payload_file (payload):
	DESC=["File payload","Use the file content (lines) as payload"]
	PARAMS=[(True,"Enter a path","file",datainput.String,"")]

	def __init__(self,file):
		payload.__init__(self)
		self.file=file

	def __len__(self):
		f=open(self.file)
		self.count=len(f.readlines())
		f.close()
		return self.count

	def initialize (self):
		self.f=open(self.file)
	
	def do_next (self):
		try:
			return self.f.next().strip()
		except StopIteration:
			self.f.close()
			raise StopIteration



class payload_range (payload):
	DESC=["Range payload","Use a numeric range (in any base) as a payload"]
	PARAMS=[(True,"Enter a range (eg 1-10,a-f)","range",datainput.String,"[A-Za-z0-9]+[^A-Za-z0-9]+[A-Za-z0-9]+"),
			(False,"Enter the number width","width",datainput.Number,1),
			(False,"Choose a numeric base","base",datainput.Option,([8,10,16],10)),
			(False,"Enter a string suffix","suffix",datainput.String,""),
			(False,"Enter a step increment for the range","step",datainput.Number,1)]

	def __init__(self,range,width=0,base=10,suffix="",step=1):    
		payload.__init__(self)
		try:
			ran=re.findall("([A-Za-z0-9]+)[^A-Za-z0-9]+([A-Za-z0-9]+)",range)[0]
			self.minimum=int(ran[0],base)
			self.maximum=int(ran[1],base)
			self.count=self.maximum - self.minimum + 1
			self.current=self.minimum
			self.width=width
			self.base=int(base)
			self.step=step
			self.suffix=suffix
		except:
			raise Exception, "Bad range format or base"

	def initialize(self):
		self.current=self.minimum
		
	def do_next (self):
		if self.current>self.maximum:
			raise StopIteration

		if self.base==16:
			lgth=len(hex(self.maximum).replace("0x",""))
			num=hex(self.current).replace("0x","")	
		elif self.base==8:
			lgth=len(oct(self.maximum)[1:])
			num=oct(self.current)[1:]
		else:
			lgth=len(str(self.maximum))
			num=str(self.current)	

		pl="%"+str(lgth)+"s"
		pl= pl % (num)
		payl=self.suffix+pl.replace(" ","0")

		if self.width:
			payl="%0"+str(self.width)+"s"
			payl=payl % (pl)
		else:
			payl=pl

		payl=payl.replace(" ","0")

		self.current+=self.step
		return self.suffix+payl
	

######################### PAYLOAD LIST

class payload_list (payload):
	PARAMS=[(True,"Enter a new line for easch string (empty line to finish)","list",datainput.ListString,"")]
	def __init__(self,list):   
		payload.__init__(self)
		self.list=list
		self.count=len(list)
		

	def initialize(self):
		self.current=0
		
	def do_next (self):
		try:
			elem=self.list[self.current]
			self.current+=1
			return elem
		except:
			raise StopIteration
		
