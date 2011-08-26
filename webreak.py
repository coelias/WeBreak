#   webreak.py: Web vulnerability scanner software
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
#   and Abel Gomez Aguila, zprian@gmail.com

import globals
from sechttp import HttpReq,HttpCMgr,httpInfoBlock,Variable
from fuzz import *
import itertools
import re
import datetime

class ReqFuzzer:
	def __init__(self,fuzzdicc,rawreq,scheme="http",independents=False):
		'''fuzzdicc={"FUZZTAG": Fuzz Object, "FUZZTAG2": Fuzz Object"}'''
		'''indepentends means if variables are dependents or independents, making a product or a zip'''

		self.fzregexs=[(re.compile("()({0})".format(i)),"") for i in fuzzdicc]
		self.httpinfo=httpInfoBlock()
		self.httpinfo.makeVars(rawreq,self.fzregexs)
		self.scheme=scheme

		self.varsAndPay=[(i,fuzzdicc[i.value]) for i in self.httpinfo.detectedVars]

		if not independents:
			self.iter=itertools.product(*[i[1] for i in self.varsAndPay])
		else:
			self.iter=itertools.zip_longest(*[i[1] for i in self.varsAndPay])

		self.stats=None

	def fuzz(self,cm,callback):
		for nxt in self.iter:
			for i in range(len(nxt)):
				self.varsAndPay[i][0].update(nxt[i])
			req=HttpReq(cm)
			req.parseRequest(self.httpinfo.getRaw(),self.scheme)
			req.performMulti(callback,str(nxt))


		

a='''GET /@FZZ@ HTTP/1.1
Host: www.site.com
user-agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)

'''

def callback(req,resp,info,excep):
	if excep:
		print (str(excep))
	else:
		lgth,wds=resp.getLengthWords()
		code=resp.code
		if code!=404:
			print ("{0:>4} {1:>5} {2:>5} {3:<20}".format(code,lgth,wds,info))

cm=HttpCMgr(threads=20)

a=ReqFuzzer({"@FZZ@":FileFuzz("/tmp/wfuzz-read-only/wordlist/general/common.txt")},a)

stat=datetime.datetime.now()
a.fuzz(cm,callback)

print ("{0:>4} {0:>5} {1:>5} {2:<20}".format("Code","Length","Words","Info"))
print ("===========================================================")

cm.waitMulti()
stat=datetime.datetime.now()-stat
