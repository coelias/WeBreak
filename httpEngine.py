import urllib
import sys

print (urllib.urlopen(sys.argv[1]).read())

