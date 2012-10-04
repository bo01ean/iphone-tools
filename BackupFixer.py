#!/usr/bin/env python
import sys
import re
import os
import sys
import fnmatch
import shutil

"""
	This script will look for important backup files in your iphone backup directory. It will copy the largest of those files into a directory

	safeMode flag makes no changes to the filesystem, only flip to True if you are completely sure

"""


files = []
candidates = {}
tmp = ""
reg = ""

outputDir = "tmp"
safeMode = True




dict ="""SMS / Text messages	1-6	sms.db	3d0d7e5fb2ce288813306e4d4636395e047a3d28	SQLite 3
Contacts / address book	2-6	AddressBook.sqlitedb	31bb7ba8914766d4ba40d6dfb6113c8b614be442	SQLite 3
Calendar	2-6	Calendar.sqlitedb	2041457d5fe04d39d0ab481178355df6781e6858	SQLite 3
Notes	4-6	notes.sqlite	ca3bc056d4da0bbf88b5fb3be254f3b7147e639c	SQLite 3
Call history	4-6	call_history.db	2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca	SQLite 3
Locations	4 - 6	consolidated.db	4096c9ec676f2847dc283405900e284a7c815836	SQLite 3
dsfdasf 12b144c0bd44f2b3dffd9186d3f9c05b917cee25  lkjsadflkjasdf iPhoto
adsfasdf b03b6432c8e753323429e15bc9ec0a8040763424 lkjsdf iPhoto backup

photos, SMS, call log and contacts
"""

def getFileNames():
  data = re.findall( ur'''[0-9a-f]{40}''', dict )# get SHA1 signatures
  print dict
  return data

  
  
  
  
  
  
  
  
  
  
  
  
  
def recurse( path ):
		print "entering:" + path
		for root, subFolders, files in os.walk( path ):  
			#print root# + " has " + subFolders
			for file in files:
				path = os.path.join( root, file)

				for h in hashNames:
					if(fnmatch.fnmatch( file, h ) ):
						#print file + " matches " + h
						s =  os.stat(path).st_size
						
						if( candidates[h]['size'] < s ):
							candidates[h]['size'] = s
							candidates[h]['path'] = path
						
						# this doesn't work!! WTF	
						if re.match( r"h", file ):
							print path + " matches REGEX too ..";
			
			for folder in subFolders:
			
				if folder == "tmp":
					return
				newPath = os.path.join( root, folder )
				recurse( newPath )

				
				
				
				
  
if __name__ == '__main__':  
	hashNames = getFileNames()
	tmp = "ur(" + "|".join(hashNames) + ")"
	reg  = re.compile(tmp)

	
	for i in hashNames: 
		print i
		candidates[i] = {'path':"",'size':0}

	recurse(".")
	
	
	try:
		os.stat( ".//" + outputDir + "//" )
	except:
		os.makedirs( ".//" + outputDir + "//" )
			
	
	for key, value in candidates.iteritems():
		print candidates[key]['path']
		
		if not safeMode
			shutil.copyfile( candidates[key]['path'], ".//" + outputDir + "//" +  key  )

		
	
	print candidates

	
	