#   datainput.py - Clases to get input data from the user
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
import sys

class data:
	@staticmethod
	def inputf(msg=""):
		sys.stdout.write(msg)
		sys.stdout.flush()
		a=sys.stdin.readline()
		return a
	
	
class Number(data):
	@staticmethod
	def input(default=None,cad="Enter a number"):
		if default:
			cad +=" [{0}]: ".format(default)
		else:
			cad+=": "
		a=data.inputf(cad)
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
		a=data.inputf(cad)
		if not a.strip() and default:
			return default
		return a.replace("\r","").replace("\n","")

class Option(data):
	@staticmethod
	def input(options,cad="Select an option"):
		print (cad)
		opts,default=options
		if default not in opts:
			raise Exception("Default not in options")
		if default:
			cad+=" [{0}]: ".format(opts.index(default)+1)
		else:
			cad+=": "

		for i in enumerate(opts,1):
			print ("{0}: {1}".format(i[0],i[1]))
		a=data.inputf(cad)
		try:
			a=int(a)
			if a not in range(1,len(opts)+1):
				raise Exception()
			return opts[a-1]
		except:
			if default:
				return default
			raise Exception("Wrong option")

class MultipleChoice(data):
	@staticmethod
	def input(opts,cad="Select one or more options (use separated numbers): "):
		for i in enumerate(opts,1):
			print ("{0}: {1}".format(i[0],i[1]))
		a=data.inputf(cad)
		try:
			a=[int(i) for i in re.findall("[0-9]+",a)]
			for i in a:
				if i not in range(1,len(opts)+1):
					raise Exception()
			return [opts[i-1] for i in a]
		except:
			if default:
				return default
			raise Exception("Wrong format")

class ListString(data):
	@staticmethod
	def input(par,cad="Enter a list of strings (end with empty string) :"):
		print (cad)
		lst=[]
		a=data.inputf().strip()
		while a:
			lst.append(a)
			a=data.inputf().strip()
		return lst

class Text(data):
	@staticmethod
	def input(msg="Enter a text"):
		msg+=" (finish with Ctl-D (Unix) or Ctl-Z+Return (Win)):\r\n"
		print (msg)
		text=[]
		while 1:
			a=sys.stdin.readline()
			text.append(a)
			if not a or a[-1]!="\n":
				break
		return "".join(text)

if __name__=="__main__":
	print (Number.input())
	print ("---------------------")
	print (Number.input(2))
	print ("---------------------")
	print (String.input("pep"))
	print ("---------------------")
	print (Option.input((["a","b","c"],"c")))
	print ("---------------------")
	print (ListString.input((["a","b","c"])))
	print ("---------------------")
	print (MultipleChoice.input((["a","b","c"])))
	print ("---------------------")
	print (Text.input())
