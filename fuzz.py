#   fuzz.py - Fuzzing classes and encoding functions
#   Copyright (C) 2011 Carlos del Ojo Elias
#   
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2, or (at your option)
#   any later version.
#   
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#   
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software Foundation,
#   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
#   
#   Written by Carlos del Ojo Elias, deepbit@gmail.com


import re
import datainput
import globals
import base64
import hashlib

if globals.VERSION <30:
	from urllib import quote
else:
	from urllib.parse import quote

class Fuzz:
	def __init__(self):
		self.count=0
		self.appended=None
		self.actual=None
		self.encoder=None

	def __iter__ (self):
		self.initialize()
		a=self.next()
		while a:
			if not self.encoder:
				yield a
			else:
				yield self.encoder(a)
			a=self.next()
		raise StopIteration

	def initialize(self):
		pass

	def setEncoder(self,enc):
		self.encoder=enc

	def __len__(self):
		if self.appended!=None:
			return self.count*len(self.appended)
		return self.count

	def append(self,fuzz):
		self.appended=fuzz
		self.appenditerator=self.appended.__iter__()

	def next (self):
		if self.appended!=None:
			try:
				if not self.actual:
					self.actual=self.do_next()
				if globals.VERSION<30:
					return self.actual+self.appenditerator.next()
				return self.actual+self.appenditerator.__next__()
			except StopIteration:
				self.actual=self.do_next()
				self.appenditerator=self.appended.__iter__()
				if globals.VERSION<30:
					return self.actual+self.appenditerator.next()
				return self.actual+self.appenditerator.__next__()
		else:
			return self.do_next()

	def do_next(self):
		raise StopIteration


class FileFuzz (Fuzz):
	DESC=["File fuzz","Use the file content (lines) as fuzz"]
	PARAMS=[(True,"Enter a path","file",datainput.String,"")]

	def __init__(self,file):
		Fuzz.__init__(self)
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
			if globals.VERSION<30:
				return self.f.next().strip()
			return self.f.__next__().strip()
		except StopIteration:
			self.f.close()
			raise StopIteration



class RangeFuzz (Fuzz):
	DESC=["Range fuzz","Use a numeric range (in any base) as a fuzz"]
	PARAMS=[(True,"Enter a range (eg 1-10,a-f)","range",datainput.String,"[A-Za-z0-9]+[^A-Za-z0-9]+[A-Za-z0-9]+"),
			(False,"Enter the number width","width",datainput.Number,1),
			(False,"Choose a numeric base","base",datainput.Option,([8,10,16],10)),
			(False,"Enter a string suffix","suffix",datainput.String,""),
			(False,"Enter a step increment for the range","step",datainput.Number,1)]

	def __init__(self,range,width=0,base=10,suffix="",step=1):    
		Fuzz.__init__(self)
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
			raise Exception("Bad range format or base")

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
		fz=self.suffix+pl.replace(" ","0")

		if self.width:
			fz="%0"+str(self.width)+"s"
			fz=fz % (pl)
		else:
			fz=pl

		fz=fz.replace(" ","0")

		self.current+=self.step
		return self.suffix+fz
	

class ListFuzz (Fuzz):
	PARAMS=[(True,"Enter a new line for easch string (empty line to finish)","list",datainput.ListString,"")]
	def __init__(self,list):   
		Fuzz.__init__(self)
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
	

######## ENCODINGS ###########################

class ENCODER:
	FNCS=None
	INFO=None
	
	@staticmethod
	def list():
		ENCODER.FNCS=dict([(getattr(ENCODER,i).__doc__.split(":")[1].split("-")[0].strip(),getattr(ENCODER,i)) for i in dir(ENCODER) if getattr(ENCODER,i).__doc__ and getattr(ENCODER,i).__doc__.startswith("ENC:")])
		ENCODER.INFO=dict([(getattr(ENCODER,i).__doc__.split(":")[1].split("-")[0].strip(),getattr(ENCODER,i).__doc__.split(":")[1].split("-")[1].strip()) for i in dir(ENCODER) if getattr(ENCODER,i).__doc__ and getattr(ENCODER,i).__doc__.startswith("ENC:")])

	@staticmethod
	def urlencode (info):
		'''ENC: urlencode - Encodes text to be used in an url'''
		return quote(info)
	
	@staticmethod
	def double_urlencode (info):
		'''ENC: double urlencode - Double urlencoding'''
		return quote(quote(info))

	@staticmethod
	def base64 (info):
		'''ENC: base64 - Encode a string to base64'''
		if globals.VERSION<30:
			return base64.standard_b64encode(info)
		return base64.b64encode(info.encode()).decode()

	@staticmethod
	def hexa (info):
		'''ENC: Html Hexadecimal - Encode a string as Hexadecimal (a -> %61)'''
		return "".join(["{0:0>2}".format(hex(ord(i))).replace("0x","%") for i in info])
	
	@staticmethod
	def sha1 (info):
		'''ENC: sha1 - Process data unsing Sha1 digest alg. '''
		hs=hashlib.sha1()
		hs.update(info.encode())
		return hs.hexdigest()
	
	@staticmethod
	def md5 (info):
		'''ENC: md5 - Process data unsing Md5 digest alg.'''
		hs=hashlib.md5()
		hs.update(info.encode())
		return hs.hexdigest()

	
	@staticmethod
	def mssql_str (info):
		'''ENC: MSsql encoding - MSsql string encoding'''
		return "+".join(["CHAR({0})".format(ord(i)) for i in info])

	@staticmethod
	def mysql_str (info):
		'''ENC: Mysql encoding - Mysql string encoding'''
		return "CHAR("+",".join([str(ord(i)) for i in info])+")"
	
	@staticmethod
	def oracle_str (info):
		'''ENC: Oracle encoding - Oracle string encoding'''
		return "||".join(["chr({0})".format(ord(i)) for i in info])

########## SHIT TO RECODE ###################

	# http://wikisecure.net/security/uri-encoding-to-bypass-idsips
	@staticmethod
	def doble_nibble_hex (info):
#		'''ENC: nibble hex - Encode a string as Hexadecimal (a -> %61)'''
		strt = ""
		con = "%%%02x"
		s=re.compile(r"/|;|=|:|&|@|\\|\?")
		for c in info:
			if s.search(c):
				strt += c
				continue
			temp = hex(ord(c))[2:]
			strt += "%%%s%%%02x" % (str(temp[:1]), ord(temp[1:]))
		return strt
			
	@staticmethod
	def binascii (info):
#		'''ENC: Binascii - Encode a string as Hexadecimal (a -> %61)'''
		res = binascii.hexlify(info.encode())		
		return res
	
	@staticmethod
	def html (info):
		res=info
		res=res.replace("<","&lt;")
		res=res.replace(">","&gt;")
		res=res.replace("\"","&quot;")
		res=res.replace("'","&apos;")
		#res=res.replace("&","&amp;")
		return res
	
	@staticmethod
	def html_decimal (info):
		new=""
		for x in info:
			new+="&#"+str(ord(x))+";"
		return new
	
	@staticmethod
	def html_hexadecimal (info):
		new=""
		for x in info:
			val="%02x" % ord(x)
			new+="&#x"+str(val)+";"
		return new
	
	@staticmethod
	def utf8_binary (info):
		new=""
		for x in info:
			val="%02x" % ord(x)
			new+="\\x"+str(val)
		return new
	
	@staticmethod
	def utf8 (info):
		new=""
		for x in info:
			val="%02x" % ord(x)
			if len(val)==2:
				new+="\\u00"+str(val)
			else:
				new+="\\u"+str(val)
		return new
	
	
	

ENCODER.list()


if __name__=="__main__":
	a=ListFuzz(["a","b","c"])
	print ([i for i in a])
	b=RangeFuzz("1-10",4,7,"@",2)
	print ([i for i in b])
	a.append(b)
	print ([i for i in a])
	w=open("/tmp/tmp.tmp","w")
	w.write("1\r\n2\r\n3\r\n4")
	w.close()
	c=FileFuzz("/tmp/tmp.tmp")
	c.append(a)
	print ([i for i in c])
	c.setEncoder(ENCODER.base64)
	print ([i for i in c])

	print("\r\n\r\n################## ENCODINGS ###################\r\n\r\n")

	for i,j in ENCODER.FNCS.items():
		print ("Encoding ({0})(Hello World!):".format(i),j("Hello World!"))
