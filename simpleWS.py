import globals
import base64
import tarfile
import mimetypes
mimetypes.init()
mimetypes.types_map['.dwg']='image/x-dwg'
mimetypes.types_map['.ico']='image/x-icon'
mimetypes.types_map['.bz2']='application/x-bzip2'
mimetypes.types_map['.gz']='application/x-gzip'

if globals.VERSION<30:
	from BaseHTTPServer import HTTPServer
	from SimpleHTTPServer import SimpleHTTPRequestHandler
	from SocketServer import ThreadingMixIn
	from urlparse import urlparse,urlunparse 
else:
	from http.server import HTTPServer,SimpleHTTPRequestHandler
	from socketserver import ThreadingMixIn
	from urllib.parse import urlparse,urlunparse 

class ThreadingServer(ThreadingMixIn, HTTPServer):
	pass

class FileMgr:
	def __init__(self,path=None,tar=None):
		self.available=set()
		if tar and not path:
			self.tar=self.iniTar(tar)
			self.METHOD="tar"
		elif path and not tar:
			self.iniPath(path)
			self.path=path
			self.METHOD="path"
		else:
			raise Exception("Bad initialization")

	
	def iniTar(self,tar):
		assert tarfile.is_tarfile(tar)
		if tar.split(".")[-1].lower() in ["tgz","gz"]:
			tar = tarfile.open("sample.tar.gz", "r:gz")
		else:
			tar = tarfile.open("sample.tar.gz", "r")
			
		for tarinfo in tar:
			if tarinfo.isreg():
				self.available.add(tarinfo.name[1:])
			elif tarinfo.isdir(): pass #print ("a directory.")
			else: pass #print ("something else.")
		return tar

	def iniPath(self,path):
		pass

	def __contains__ (self,item):
		return item in self.available
	
	def __getitem__(self,item):
		if self.METHOD=="tar":
			return self.tar.extractfile("."+item).read()
		
class simpleRH(SimpleHTTPRequestHandler):
	def do_GET(self):
		global FM
		# self.path

		if self.path in FM:
			self.send_response(200)
			ext=self.path.split(".")[-1].lower()
			if ext in mimetypes.types_map:
				mime=mimetypes.types_map[ext]
				self.send_header("Content-Type", mime)
			self.end_headers()
			self.wfile.write(FM[self.path])
		else:
			self.send_response(404)
			self.send_header("Content-Type", mimetypes.types_map[".html"])
			self.end_headers()
			self.wfile.write("<h1>File not found (404)</h1><br>We are so sorry :(<br><br><br>That's no so bad, we will die someday anyway<br>Have a good day :D".encode())


	do_POST=do_GET

FM=FileMgr(tar="sample.tar.gz")	



serveraddr = ('', 8765)
srvr = ThreadingServer(serveraddr, simpleRH)
srvr.serve_forever()

