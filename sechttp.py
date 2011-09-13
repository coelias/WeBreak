#   sechttp.py: a HTTP protocol security abstraction by Carlos del Ojo (deepbit@gmail.com)
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

# This module uses httplib2 (http://code.google.com/p/httplib2/) and can be used with with pyCurl (http://pycurl.sourceforge.net/)

import re
import socks
import threading
import hashlib
import globals


if globals.VERSION>30:
	from queue import Queue
else:
	from Queue import Queue

HTTPCODES={ '100':"Continue", '101':"Switching Protocols", '200':"OK", '201':"Created", '202':"Accepted", '203':"Non-Authoritative Information", '204':"No Content", '205':"Reset Content", '206':"Partial Content", '300':"Multiple Choices", '301':"Moved Permanently", '302':"Found", '303':"See Other", '304':"Not Modified", '305':"Use Proxy", '306':"(Unused)", '307':"Temporary Redirect", '400':"Bad Request", '401':"Unauthorized", '402':"Payment Required", '403':"Forbidden", '404':"Not Found", '405':"Method Not Allowed", '406':"Not Acceptable", '407':"Proxy Authentication Required", '408':"Request Timeout", '409':"Conflict", '410':"Gone", '411':"Length Required", '412':"Precondition Failed", '413':"Request Entity Too Large", '414':"Request-URI Too Long", '415':"Unsupported Media Type", '416':"Requested Range Not Satisfiable", '417':"Expectation Failed", '500':"Internal Server Error", '501':"Not Implemented", '502':"Bad Gateway", '503':"Service Unavailable", '504':"Gateway Timeout", '505':"HTTP Version Not Supported"}

class HttpCMgr:
	'''Connection Manager: Used by any HttpReq Object in order to create http connections. It's a wrapper of any other HTTP engine, like PyCurl, Httplib2, Requests, or any other'''
	class Connection:
		# Every Connection has a request function wich returns a rawresponse in order to be parsed
		def __init__(self):
			pass

	class httplib2Connection(Connection):
		# httlib2Wrapper
		def __init__(self,proxy=None):
			proxy_info=None
			if proxy:
				proxy_info = httplib2.ProxyInfo(socks.PROXY_TYPE_HTTP, proxy[0], int(proxy[1]))
			HttpCMgr.Connection.__init__(self)
			self.conn=httplib2.Http(proxy_info=proxy_info)


		def request(self,method,url,headers,body,auth,redirections):
			if auth:
				u,p,d=auth
				self.conn.add_credentials(u,p,d)

			try:
				resp,content=self.conn.request(url,method=method,redirections=redirections,body=body,headers=headers)
				if globals.VERSION>=30:
					content=content.decode()
	
				if str(resp["status"]) in HTTPCODES:
					msg=HTTPCODES[str(resp["status"])]
				else:
					msg="Unknown"
	
				rawResponse="HTTP/1.1 {0} {1}\r\n".format(resp["status"],msg)
				del resp["status"]
				for i,j in resp.items():
					rawResponse+="{0}: {1}\r\n".format(i,j)
				rawResponse+="\r\n{0}".format(content)
			except Exception as e:
				if auth:
					self.conn.clear_credentials()
				raise e
				
			if auth:
				self.conn.clear_credentials()

			return rawResponse
			
	def __init__(self,threads=1,proxyinfo=None):
		'''You can provide the number of threads to use and an optional Proxy'''
		assert threads>0
		self.ConnSem=threading.Semaphore()
		self.__Connections=[]
		self.__Threads=threads
		self.__MultiQueue=Queue()
		self.__proxyinfo=proxyinfo
		self.__createConnections(threads)
		self.__createWorkers(threads)

	def __createWorkers(self,threads):
		#obvious
		for i in range(threads):
			t=threading.Thread(target=self.__requestAsynchProcessor)
			t.daemon=True
			t.start()

	def __createConnections(self,nc):
		# I use __releaseConnection in order to avoid race conflicts
		for i in range(nc):
			self.__releaseConnection(HttpCMgr.httplib2Connection(self.__proxyinfo))

	def __getConnection(self):
		# Semaphore acces to the connection list
		self.ConnSem.acquire()
		if self.__Connections:
			conn=self.__Connections.pop(0)
		else:
			conn=None
		self.ConnSem.release()

		if not conn:
			raise HttpCMgr.ThreadsExceded()
		return conn

	def __releaseConnection(self,c):
		# Semaphore acces to the connection list
		self.ConnSem.acquire()
		self.__Connections.append(c)
		self.ConnSem.release()
		
		
	def __requestAsynchProcessor(self):
		# Worker Function
		while True:
			# It gets a job, params for the request function, Request, callback
			# function to call to, and additional info to pass to the callback function
			params,httpreq,callback,info=self.__MultiQueue.get()
			if params=="STOP":			# If params = "STOP" string, then the worker will stop, and then will delete a conenction
				self.__MultiQueue.task_done()
				break

			# It gets the response, and executes the callback before assigning it to the original request
			# I do that, because you can use several threads with the same Request Object, so
			# calling the callback funcion before asigning, I ensure response do not overwrite each other
			# This is mainly for FUZZING purposes, due to you don't need the original request but the response object
			# and maybe you need some info about the fuzzing  with the response
			try:									
				conn=self.__getConnection()			# get a connection object
				try:								
					rawResponse=conn.request(**params)	# perform the request
					resp=Response()
					resp.parseResponse(rawResponse)		# Creating and parsint the output
					if callback:
						callback(httpreq,resp,info,None)		# Calling the callback
					httpreq.response=resp
				except Exception as e:
					self.__releaseConnection(conn)
					raise e
				self.__releaseConnection(conn)
			except Exception as e:
				if callback:
					callback(httpreq,None,info,e)
			self.__MultiQueue.task_done()

		self.__getConnection()  # When a worker finishes, It removes a connection from the connection list

	def setThreads(self,threads):
		'''If you want to change the number of threads while running, this function lets you increase or decrease the amount of threads.'''
		assert threads>0
		if threads>self.__Threads:
			self.__createWorkers(threads-self.__Threads)        # Increase workers
			self.__createConnections(threads-self.__Threads)	# Increase connections
		else:
			for i in range(self.__Threads-threads):			
				self.__MultiQueue.put(("STOP",None,None))		# We put new jobs with "STOP" sting inside
		self.__Threads=threads
		

	def MakeRequest(self,method,url,headers,body,auth,redirections,httpReq):
		conn=self.__getConnection()
		try:
			rawResponse=conn.request(method,url,headers,body,auth,redirections)
			resp=Response()
			resp.parseResponse(rawResponse)
			httpReq.response=resp
		except Exception as e:
			self.__releaseConnection(conn)
			raise e
		self.__releaseConnection(conn)

	def MakeRequestMulti(self,callback,method,url,headers,body,auth,redirections,httpReq,info=None):
		task=({'method':method,'url':url,'headers':headers,'body':body,'auth':auth,'redirections':redirections},httpReq,callback,info)
		self.__MultiQueue.put(task)

	def waitMulti(self):
		'''Used to wait until all threads finish to process all the requests.'''
		self.__MultiQueue.join()
			


try:
	import pycurl
	PYCURL=True
	raise Exception("a")
except:
	PYCURL=False
	if globals.VERSION<30:
		import httplib2
		from StringIO import StringIO
		from urlparse import urlparse,urlunparse
	else:
		import httplib2_3 as httplib2
		from io import StringIO
		from urllib.parse import urlparse,urlunparse

HttpQueryVarsFormats=[(re.compile("([^?=&]+)(?:=([^&]*))?"),"=")]
HttpPathVarsFormats=[(re.compile("([^/~]+)~([^/]+)"),"~"),
					(re.compile("([^/=]+)=([^/]+)"),"=")
					]
HttpHeadersVarsFormats=[(re.compile("([^;,: ]+)=([^=:,;]+)"),"=")]

class Variable:
	'''Variable Object wich can be modified and recovered.'''
	def __init__(self,name,value="",eq="=",extraInfo=""):
		if value==None:
			value=""
		#: Variable name (or key)
		self.name=name
		#: Variable value
		self.value=value
		self.__initValue=value
		self.extraInfo=extraInfo
		self.__eq=eq
	
	def update(self,val):
		'''Change the variable value.'''
		self.value=val

	def append(self,val):
		'''Appends information to the variable value'''
		self.value+=val

	def restore(self):
		'''Restores the variable to the first value assigned.'''
		self.value=self.__initValue

	def copy(self):
		'''Copies the current variable and returns a new variable with the same information.'''
		nv= Variable(self.name,self.__initValue,self.__eq,self.__extraInfo)
		nv.update(self.value)
		return nv

	def change(self,newval):
		'''Permanent change of the value, overwriting the initial value.'''
		self.__initValue=self.value=newval

	def info(self):
		'''String representation of the variable -> [ %s : %s ]'''
		return "[ %s : %s ]" % (self.name,self.value)
	
	def __str__(self):
		'''Raw representation of the variable '''
		return "".join([self.name,self.__eq,self.value])

	

class httpInfoBlock:
	def __init__(self):
		self.detectedVars=[]
		self.allInfo=None

	def makeVars(self,origcad,regexpool,info=None):
		'''This function receives a source string, and a pool of regexps to create new Variables objects'''
		self.detectedVars=[]
		vars=[]
		for i,j in regexpool:
			a=i.finditer(origcad)
			for k in a:
				# Groups variables, sorting the first the last found, with position and lentgh (a=b&c=d) ==> [[c=d,4, 3],[a=b,0, 3]]
				vars.append([Variable(k.groups()[0],k.groups()[1],j,extraInfo=info),k.start(),len(k.group())])

		vars.sort(key=self.sortf,reverse=True)

		varset=[]
		cad=origcad

		for i in vars:
			if i[1]+i[2]>len(cad) or not i[2]:
				continue
			end=cad[i[1]+i[2]:]
			if end:
				varset.insert(0,end)
			varset.insert(0,i[0])
			self.detectedVars.append(i[0])
			cad=cad[:i[1]]
		if cad:
			varset.insert(0,cad)
		self.allInfo=varset
	
	def getRaw(self):
		if not self.allInfo:
			return ""
		return "".join([str(i) for i in self.allInfo])

	def appendString(self,cad):
		self.allInfo.append(cad)

	def appendVariable(self,var):
		self.allInfo.append(var)
		self.detectedVars.append(var)
	
	def __str__(self):
		return self.getRaw()

	def sortf(self,a):
		'''Function to sort using 2nd field and decreasing'''
		return a[1]

	def getVars(self):
		return self.detectedVars


class httpUrl():
	def __init__(self,uri):
		parseurl=urlparse(uri)
		self.scheme=parseurl[0]
		self.netloc=parseurl[1]
		self.__path=httpInfoBlock()
		self.__path.makeVars(parseurl[2],HttpPathVarsFormats,"GET")
		self.__params=parseurl[3]
		self.__query=httpInfoBlock()
		self.__query.makeVars(parseurl[4],HttpQueryVarsFormats,"GET")
		self.__fragment=parseurl[5]

	def __getattr__ (self,name):
		if name=="urlWithoutVariables":
			return urlunparse((self.scheme,self.netloc,str(self.path),self.__params,"",""))
		elif name=="pathWithVariables":
			return urlunparse(("","",str(self.path),self.__params,str(self.query),self.__fragment))
		elif name=="completeUrl":
			return urlunparse((self.scheme,self.netloc,str(self.path),self.__params,str(self.query),self.__fragment))
		elif name=="urlWithoutPath":
			return urlunparse((self.scheme,self.netloc,"","","",""))
		elif name=="path":
			return self.__path.getRaw()
		elif name=="query":
			return self.__query.getRaw()
		else:
			raise AttributeError

	def getVars(self):
		return self.__path.getVars()+self.__query.getVars()

class httpHeaders():
	def __init__(self):
		self.headers={}
		self.KeysWithVariables=["Cookie"]

	def __setitem__(self,key,value):
		key="-".join([i.capitalize() for i in key.split("-")]).strip()
		if key in ["Content-Length","If-Modified-Since","If-None-Match"]:
			return
		if key in self.KeysWithVariables:
			self.headers[key]=httpInfoBlock()
			self.headers[key].makeVars(value,HttpHeadersVarsFormats,"Header")
		else:
			self.headers[key]=value

	def __getitem__(self,key):
		key="-".join([i.capitalize() for i in key.split("-")]).strip()
		if key not in self.headers:
			return ""
		return str(self.headers[key])

	def __delitem__(self,key):
		key="-".join([i.capitalize() for i in key.split("-")]).strip()
		if key not in self.headers:
			raise Exception("Header ({0}) not found".format(key))
		del self.headers[key]

	def __contains__(self,key):
		key="-".join([i.capitalize() for i in key.split("-")]).strip()
		return key in self.headers

	def __str__(self):
		cad=""
		for i in self.headers:
			cad+="{0}: {1}\r\n".format(i,self[i])
		return cad
	
	def __iter__(self):
		for i in self.headers:
			yield i,self[i]
		raise StopIteration

	def processed(self):
		return dict([(i,j) for i,j in self])

	def getVars(self):
		vars=[]
		for key,i in self.headers.items():
			if key in self.KeysWithVariables:
				vars+=i.getVars()
		return vars

class HttpReq:
	'''Http request Object, it uses a Connection Manager by default with only one thread and no proxy.
	
Attributes:
	* urlWithoutVariables
	* pathWithVariables
	* completeUrl
	* urlWithoutPath
	* path
	* response 
'''
	
	DEFAULTCMGR=HttpCMgr()

	def __init__(self,CMGR=None):
		if not CMGR:
			CMGR=HttpReq.DEFAULTCMGR
		self.__METHOD="GET"
		self.CMGR=CMGR

		self.headers=httpHeaders()
		self.response=None

		self.__followLocation=2
		self.__timeout=None
		self.__totaltimeout=None
		self.__auth=None
		self.__postdata=httpInfoBlock()


	def __getattr__ (self,name):
		if name=="urlWithoutVariables":
			return self.url.urlWithoutVariables
		elif name=="pathWithVariables":
			return self.url.pathWithVariables
		elif name=="completeUrl":
			return self.url.completeUrl
		elif name=="urlWithoutPath":
			return self.url.urlWithoutPath
		elif name=="path":
			return self.url.path
		elif name=="finalUrl":
			if self.__finalurl:
				return self.__finalurl
			return self.completeUrl
		elif name=="postdata":
			if self.ContentType=="application/x-www-form-urlencoded":
				return self.__variablesPOST.urlEncoded()
			elif self.ContentType=="multipart/form-data":
				return self.__variablesPOST.multipartEncoded()
			else:
				return self.__uknPostData
		else:
			raise AttributeError

	################################## METHODS ######################################

	def setCmgr(self,cmgr):
		'''Set a new Connection manager'''
		self.CMGR=cmgr

	def setUrl (self, urltmp):
		'''Set the URL you want to make the request'''
		self.url=httpUrl(urltmp)

	def setPostData(self,data):
		'''Add Post data to the request'''
		self.__METHOD="POST"
		self.__postdata.makeVars(data,HttpQueryVarsFormats,"POST")

	def getVars(self):
		'''Returns all detected variables inside the request in a list of sechttp.Variable Objects'''
		return self.url.getVars()+self.__postdata.getVars()+self.headers.getVars()

	def getUrlVars(self):
		'''Get variables only from URL'''
		return self.url.getVars()

	def getHeadingsVars(self):
		'''Get variables only from the headings'''
		return self.headers.getVars()

	def getPostVars(self):
		'''Get variable only from the body'''
		return self.__postdata.getVars()


	#----------------------------------- Location --------------------------------------#
	def setRedirect(self,value):
		'''Set the number on redirections to follow and avoiding an infinite loop (2 by default)'''
		self.__followLocation=value

	#----------------------------------- Auth --------------------------------------#
	def setAuth (self,user,passwd,domain=""):
		'''Set user password and an optional domain for authentication'''
		self.__auth=(user,passwd,domain)

	def getAuth (self):
		'''returns the authentication provided in a tuple (u,p,d)'''
		return self.__auth


	#----------------------------------- Headers ----------------------------------#
	def __getitem__(self,key):
		'''Use [] to get a header'''
		return self.headers[key]

		self.headers[key]=value

	def __contains__(self,key):
		'''Use 'in' key to guess if it contains a header'''
		return key in self.headers
	
	################################################################################

	def setMethod(self,met):
		'''Specify the method if you want to use another different from ['POST','GET'] (like 'HEAD' or 'PUT')'''
		self.__METHOD=met.upper()

	def logReq(self):
		Semaphore_Mutex.acquire()
		f=open("/tmp/globals.REQLOG-%d-%d" % (date.today().day,date.today().month) ,"a")
		f.write( strftime("\r\n\r\n############################ %a, %d %b %Y %H:%M:%S\r\n", localtime()))
		f.write(self.getAll())
		f.close()
		Semaphore_Mutex.release()

	def getAll(self):
		'''Get the RAW request, Heading, headers and body'''
		cad='''{0} {1} {2}\r\n{3}'''.format(self.__METHOD,self.pathWithVariables,"HTTP/1.1",str(self.headers))
		if self.__METHOD in ["POST","PUT"]:
			cad+="\r\n"+self.__postdata.getRaw()
		return cad

	def perform(self):
		'''Performs the request, then you can access the response through the response attribute'''
		if globals.REQLOG:
			self.logReq()

		if self.__METHOD=="POST":
			self.headers["content-type"]="application/x-www-form-urlencoded"

		self.CMGR.MakeRequest(self.__METHOD,self.completeUrl,self.headers.processed(),self.__postdata.getRaw(),self.__auth,redirections=self.__followLocation,httpReq=self)

	def performMulti(self,callback=None,info=None):
		'''This function is used to perform threaded requests. You can specify a callback function callen when the connection manager finishes the request and additional info tied to the request.

Callback function header: def callbackfunc(req,resp,info,excep):
	* req: Original request
	* resp: Response
	* info: info provided by HttpReq.performMulti()
	* excep: Exception object if the request failed'''

		if globals.REQLOG:
			self.logReq()
		
		self.CMGR.MakeRequestMulti(callback,self.__METHOD,self.completeUrl,self.headers.processed(),self.__postdata.getRaw(),self.__auth,redirections=self.__followLocation,httpReq=self,info=info)


	def parseRequest(self,rawreq,scheme):
		'''Parse a RAW request in a string and overwrites the current object.'''
		par=StringIO(rawreq)
		head=par.readline().strip()
		headings={}
		h=par.readline().strip()
		while h:
			k,v=h.split(":",1)
			headings[k.strip().lower()]=v.strip()
			h=par.readline().strip()
		body=par.read().strip()

		head=head.split()

		self.setUrl("{0}://{1}{2}".format(scheme,headings["host"],head[1]))
		for i,j in headings.items():
			self.headers[i]=j

		if body and head[0]!='GET':
			self.setPostData(body)
		self.__METHOD=head[0]



class Response:
	'''HTTP Response Object
	Attributes:
	* code (status code)
	* message (status message) '''

	def __init__ (self,protocol="",code="",message=""):
		self.protocol=protocol         # HTTP/1.1
		self.code=code			# 200
		self.message=message		# OK
		self.__headers=[]		# bueno pues las cabeceras igual que en la request
		self.__content=""		# contenido de la response (si i solo si Content-Length existe)

		self.attrValDic={}

	def copy(self):
		'''Returns another Response copy'''
		a=Response()
		a.parseResponse(self.getAll())
		return a

	def getMd5(self):
		'''Returns md5 of the http response content (html or whatever)'''
		m = hashlib.md5()
		if globals.VERSION<30:
			m.update(self.__content)
		else:
			m.update(self.__content.encode())
		return m.hexdigest()

	def getLengthWords(self):
		'''Returns Length and words in a tuple (l,w)'''
		return len(self.__content),self.__content.count(" ")

	def addHeader (self,key,value):
		k="-".join([i.capitalize() for i in key.split("-")]).strip()
		self.__headers+=[(k,value)]

	def delHeader (self,key):
		for i in self.__headers:
			if i[0].lower()==key.lower():
				self.__headers.remove(i)

	def __getitem__ (self,key):
		'''Returns a header value or None if it wasn't found'''
		for i,j in self.__headers:
			if key.lower()==i.lower():
				return  j
		return None

	def getCookie (self):
		'''Returns the Cookie.'''
		str=[]
		for i,j in self.__headers:
			if i.lower()=="set-cookie":
				str.append(j)
		return  "; ".join(str)

	def has_header (self,key):
		'''Checks if there is the header key.'''
		for i,j in self.__headers:
			if i.lower()==key.lower():
				return True
		return False
	
	def getLocation (self):
		'''Gets the Location value if the header was provided.'''
		for i,j in self.__headers:
			if i.lower()=="location":
				return j
		return None

	def header_equal (self,header,value):
		for i,j in self.__headers:
			if i==header and j.lower()==value.lower():
				return True
		return False

	def getHeaders (self):
		return self.__headers

	def getContent (self):
		'''Returns the content of the response'''
		return self.__content

	def getTextHeaders(self):
		string=str(self.protocol)+" "+str(self.code)+" "+str(self.message)+"\r\n"
		for i,j in self.__headers:
			string+=i+": "+j+"\r\n"
		return string

	def getAll (self):
		'''Returns all the response, including heading and headers'''
		string=self.getTextHeaders()+"\r\n"+self.getContent()
		return string

	def Substitute(self,src,dst):
		a=self.getAll()
		b=a.replace(src,dst)
		self.parseResponse(b)

	def getAll_wpost (self):
		string=str(self.protocol)+" "+str(self.code)+" "+str(self.message)+"\r\n"
		for i,j in self.__headers:
			string+=i+": "+j+"\r\n"
		return string

	def parseResponse (self,rawResponse):
		'''Parses a Raw response from a string and replaces the current object'''
		
		par=StringIO(rawResponse)

		header=par.readline()
		try:
			self.protocol,self.code,self.message=re.findall("(HTTP\S+) ([0-9]+)\s*(.*)",header)[0]
		except:
			self.protocol="Unknown"
			self.code="999"
			self.message="BUG: Parsing Error"

		self.code=int(self.code)

		self.__headers=[]
		line=par.readline().strip()
		while line:
			k,v=re.findall("^([^:]+):\s*(.*)\s*$",line)[0]
			line=par.readline().strip()
			self.addHeader(k,v)

		self.__content=par.read()

		self.delHeader("Transfer-Encoding")
