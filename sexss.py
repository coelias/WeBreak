#   sexss.py: Secure XSS tester by Carlos del Ojo (deepbit@gmail.com) and Abel Gomez (zprian@gmail.com)
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
#		   and Abel Gomez Aguila, zprian@gmail.com

from sechttp import *
import sys
from fuzz import ENCODER
import re
import getopt


class XssTest:
	XSS_SET=[
		["[<]!--[#]echo%20var=[']HTTP_USER_AGENT[']%20--[>]" , "XSSIPWNR" , "SSI"],
		['XSS[\']PWNR', 'XSS\'PWNR', "'"],
		['XSS["]PWNR','XSS"PWNR' ,'"'],
		['XSS[<]PWNR','XSS<PWNR' ,'<'],
		['XSS[>]PWNR','XSS>PWNR' ,'>'],
		['XSS[(]PWNR','XSS(PWNR' ,'('],
		['XSS[)]PWNR','XSS)PWNR' ,')'],
		['XS-[<SCRIPT>]alert[(]document.cookie[)<]/SCRIPT[>]-SPWNR','XS-<SCRIPT>alert(document.cookie)</SCRIPT>-SPWNR' ,'Scripting'],
		['XS-[<]scr[<]script[>]ipt[>]-SPWNR','XS-<script>-SPWNR' ,'Scripting']
	]


	enc_funcs=[lambda x: x,ENCODER.urlencode, ENCODER.double_urlencode, ENCODER.triple_urlencode, ENCODER.hexa, ENCODER.html_unicode]


	SCOPETAGS=['a','abbr','acronym','address','applet','tt','i','b','big','small','bdo','blockquote','body','button','caption','center','em','strong','dfn','code','samp','kbd','var','cite','dd','del','dir','div','dl','dt','fieldset','font','form','frameset','h1','h2','h3','h4','h5','h6','head','p','html','iframe','ins','label','legend','li','map','menu','noframes','noscript','option','object','','optgroup','ol','pre','q','s','strike','script','select','span','style','sub','sup','table','tbody','td','tr','textarea','tfoot','th','thead','title','u','ul','article','aside','audio','canvas','command','datalist','details','figure','footer','header','hgroup','keygen','mark','meter','nav','output','ruby','rt','rp','section','summary','time','video']

	THISTAG=re.compile("^(!--|[a-z]+ |![a-z]+ )")
	PRETAGS=re.compile("<[^ >]+")
	LETTERS=re.compile("[a-z!-]+")


	def __init__(self,req):	
		self.req=req
		self.results=None

	def scope(self):
		
		sco=None
		curtag=None

		resp=self.req.response.getContent().lower()
		pos=resp.index("xsspwnr")
		quotes=0
		dquotes=0
		while pos>0:
			pos-=1
			if resp[pos]=="<":
				curtag=XssTest.THISTAG.findall(resp[pos+1:])[0]
					
				if dquotes%2 or quotes%2:
					if dquotes%2:
						sco="TAGPROP:\""
					else:
						sco="TAGPROP:'"
					break
				sco="TAG"
				break
			elif resp[pos]==">":
				sco="PAGE"
				break
			elif resp[pos]=="'":
				quotes=+1
			elif resp[pos]=="\"":
				dquotes=+1

		tagcount={}
		deltags=[]
		pretags=XssTest.PRETAGS.findall(resp[:pos])
		for i in pretags:
			i=i[1:]
			if i[0]=='/' and i[1:] in XssTest.SCOPETAGS:
				tagcount.setdefault(i[1:],0)
				tagcount[i[1:]]-=1
			elif i in XssTest.SCOPETAGS:
				tagcount.setdefault(i,0)
				tagcount[i]+=1
			else:
				deltags+=i

		out=[]
	
		for i in pretags:
			i=XssTest.LETTERS.findall(i)[0]
			if i in XssTest.SCOPETAGS and tagcount[i]!=0:
				out.append(i)

		return {'scope':sco,'intags':out,'insidetag':curtag}




		

	def test(self,allVars=True,post=False,get=False,headings=False,varSet=None):
		assert allVars or post or get or headings

		if varSet:
			vars=varSet
		else:
			vars=[]

			if allVars and not post and not get and not headings:
				post=get=headings=True

			# We need a tuple in order to identify the Get variables cos in execute we need to specify inUrl=True
			if get: vars+=[i for i in self.req.getUrlVars()]
			if headings: vars+=[i for i in self.req.getHeadingsVars()]
			if post: vars+=[i for i in self.req.getPostVars()]
		results=[]


		for v in vars:
			v.update("XSSPWNR")
			self.req.perform()
			v.restore()
			if "xsspwnr" in self.req.response.getContent().lower():
				scope=self.scope()
			else: continue

			scope["varname"]=v.name
			listinj=[]

			#print ("#",scope,"#")
			for test,search,injtype in XssTest.XSS_SET:
				for enc in XssTest.enc_funcs:
					encsections=re.finditer("(\[[^\]]+\]|[^\[]+)",test)
					enctest=""
					for s in encsections:
						txt=s.group()
						if txt[0]=="[" and txt[-1]=="]":
							enctest+=enc(txt[1:-1])
						else:
							enctest+=txt

					v.update(enctest)
					self.req.perform()
					v.restore()
					if search.lower() in self.req.response.getContent().lower():
						listinj.append((injtype,enctest))
						break

			scope["injections"]=listinj
			results.append(scope)

		self.results=results





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
		print ("Usage: ./sexss.py [--xml] [-D(ebug)] [-d POSTDATA] [-b COOKIE] [-x PROXY] URL")
		sys.exit(-1)

	s=XssTest(a)

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
		for i in s.results:
			print ("# -------------------------------------")
			print (i)
			print ("# -------------------------------------")
