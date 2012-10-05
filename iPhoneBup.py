#!/usr/bin/env python
"""
iPhoneBup - a iPhone backup media extractor written in Python by Nathan Trujillo github.com/bo01ean

What it does:
	This script recursively scans your backup directories,  searches for media and extracts them into folder of the users choosing.
	It uses iPhone's Manifest.mbdb file which later versions of IOS use to store backup information
	It also uses a spoofed hash list to backup media files


Why did you write this:
	After upgrading my iPhone a few days ago, I lost my backup after iTunes forgot to create a Manifest file for it.
	Since the files were still on disk, though obfuscated, I knew there was a way to get them back, and this script will do it for you.

Warning:
	I am not responsible if this script kicks your dog, scratches your new car or deletes your files. Please use at your own risk.

To Use:
	Check it out from git: https://github.com/bo01ean/iphone-tools.git
	be sure python is installed and in your path
	run this script from the command line and this script should do the rest, auto-magically

Notes:	
	the safeMode flag makes no changes to the filesystem, only flip to False if you are completely sure!
	this script does not backup app data since there are naming convention issues


This script uses code by galloglass on stackoverflow 
User Robert Munafo posted an updated version:
http://stackoverflow.com/questions/3085153/how-to-parse-the-manifest-mbdb-file-in-an-ios-4-0-itunes-backup
	
"""
import sys
import hashlib
import re
import os
import platform
import shutil



"""
User defined variables
"""


safeMode = False
outputDir = "Extracted"
minSize = 1 * 1024 * 1024# size in k of the smallest file you want to backup












"""
Do not change anything below this line unless you know what you are doing :)
"""




iPhoneImageDigestBank, mbdx, sizes, extracted = {}, {}, {}, {}







"""
	We try to determine home directory -> backup location
"""



#http://stackoverflow.com/questions/626796/how-do-i-find-the-windows-common-application-data-folder-using-python
try:
    from win32com.shell import shellcon, shell            
    homedir = shell.SHGetFolderPath(0, shellcon.CSIDL_APPDATA, 0, 0)
	
except ImportError: # quick semi-nasty fallback for non-windows/win32com case
    homedir = os.path.expanduser("~")



workingDir = {"DDarwin":"/Volumes/KELUSB-2012/iTunes Backups",
				"Darwin":"~/Library/Application Support/MobileSync/Backup",
					"Windows":homedir + "\\AppData\\Roaming\\Apple Computer\\MobileSync\\Backup\\" }



"""
	We spoof media paths
"""    	
def buildiPhoneImageDigestBank():
	# Media/DCIM/100APPLE/IMG_0001.MOV|JPG
	print "Spoofing .."   
	path = "Media/DCIM/"
	camStart = 100;
	imgInc = 1;
	types = {"JPG","MOV"}
	i = 0
      
	for camInc in range(camStart, 105):
		#print camInc
		i+=1
		for imgInc in range( ( ( i * 1000 ) - 1000 ), 1000 * i ):   
			#print str( camInc ) + "->" + str( imgInc )
			for t in types:
				fullpath = path + "{0:03d}".format(camInc) + "APPLE" + "/IMG_" + "{0:04d}".format(imgInc) + "." + t
				
   				encryptMe = "MediaDomain-" + fullpath
  	 			#print encryptMe
  	 			hash = hashlib.sha1( encryptMe )
				iPhoneImageDigestBank[hash.hexdigest()] = fullpath;



"""
	We extract files from iPhone backup database
	Mediadomain is most interesting
"""

def backupFromDatabase( file ):

	mbdb = process_mbdb_file( file )
	
	for offset, fileinfo in mbdb.items():
		if offset in mbdx:
			fileinfo['fileID'] = mbdx[offset]
			
			
			if not re.match(ur"^App", fileinfo['domain'] ) and fileinfo['filelen'] >= minSize and ((fileinfo['mode'] & 0xE000) == 0x8000):# and re.match(ur"[^THM]", fileinfo['filename']):				
				#print fileinfo['domain']

				backupFileCopy( fileinfo['fileID'], fileinfo['filename'], file )				
				#extracted[fileinfo['domain']] = extracted.get(fileinfo['domain'],0) + fileinfo['filelen']
										
		else:
			fileinfo['fileID'] = "<nofileID>"
			print >> sys.stderr, "No fileID found for %s" % fileinfo_str(fileinfo)
		
		
		if fileinfo['filelen'] > 0:
			if (fileinfo['mode'] & 0xE000) == 0x8000:
				sizes[fileinfo['domain']] = sizes.get(fileinfo['domain'],0) + fileinfo['filelen']

			
def backupFileCopy(hash, name, file, dumpDir=outputDir):

	#ABSOLUTE MODE
	dest =  os.path.join( os.getcwd(), dumpDir)
	#RELATIVE
	#dest = "./" + dumpDir
	
	for p in name.split("/"):
		dest = os.path.join( dest, p  )					

	DIR =  os.path.split( dest )[0]

	#print "DIR = " + DIR
	
	if not safeMode:
		try:
			os.stat( DIR )
		except:
			os.makedirs( DIR )
			
		src =  os.path.join( os.path.split( file )[0], hash ) 
		
		if( os.path.exists( src ) ):						
			if( os.path.exists( dest ) ):
				if( os.path.getsize( src ) > os.path.getsize( dest ) ):
					print ">>> src > dest so copying " + dest
					shutil.copyfile( src,  dest )
				#else:
				#	print ">>> same file..."		
			else:
				print ">>> dest doesn't exist, so copying " + src + "->" + dest 	
				shutil.copyfile( src,  dest )
		#else:
		#	print ">>> src doesn't exist :("



"""
	We scan through hashes and copy to file system if necessary
"""
def extractMediaFromSpoofedHashes( dir ):
	print "Extracting via hash names from " + dir
	for hash, path in iPhoneImageDigestBank.items():
		if( os.path.exists( dir + "//" + hash ) ):
			backupFileCopy(hash, path, dir + "//pizza", outputDir + "-viahashes" )
		if( os.path.exists( dir + "//" + hash + ".mdbackup" ) ):
			backupFileCopy(hash + ".mdbackup", path, dir + "//pizza", outputDir + "-viahashes" )		























def getint(data, offset, intsize):
    """Retrieve an integer (big-endian) and new offset from the current offset"""
    value = 0
    while intsize > 0:
        value = (value<<8) + ord(data[offset])
        offset = offset + 1
        intsize = intsize - 1
    return value, offset

def getstring(data, offset):
    """Retrieve a string and new offset from the current offset into the data"""
    if data[offset] == chr(0xFF) and data[offset+1] == chr(0xFF):
        return '', offset+2 # Blank string
    length, offset = getint(data, offset, 2) # 2-byte length
    value = data[offset:offset+length]
    return value, (offset + length)
	
def process_mbdb_file(filename):
    mbdb = {} # Map offset of info in this file => file info
    data = open(filename, "rb").read()
    if data[0:4] != "mbdb": raise Exception("This does not look like an MBDB file")
    offset = 4
    offset = offset + 2 # value x05 x00, not sure what this is
    while offset < len(data):
        fileinfo = {}
        fileinfo['start_offset'] = offset
        fileinfo['domain'], offset = getstring(data, offset)
        fileinfo['filename'], offset = getstring(data, offset)
        fileinfo['linktarget'], offset = getstring(data, offset)
        fileinfo['datahash'], offset = getstring(data, offset)
        fileinfo['unknown1'], offset = getstring(data, offset)
        fileinfo['mode'], offset = getint(data, offset, 2)
        fileinfo['unknown2'], offset = getint(data, offset, 4)
        fileinfo['unknown3'], offset = getint(data, offset, 4)
        fileinfo['userid'], offset = getint(data, offset, 4)
        fileinfo['groupid'], offset = getint(data, offset, 4)
        fileinfo['mtime'], offset = getint(data, offset, 4)
        fileinfo['atime'], offset = getint(data, offset, 4)
        fileinfo['ctime'], offset = getint(data, offset, 4)
        fileinfo['filelen'], offset = getint(data, offset, 8)
        fileinfo['flag'], offset = getint(data, offset, 1)
        fileinfo['numprops'], offset = getint(data, offset, 1)
        fileinfo['properties'] = {}
        for ii in range(fileinfo['numprops']):
            propname, offset = getstring(data, offset)
            propval, offset = getstring(data, offset)
            fileinfo['properties'][propname] = propval
        mbdb[fileinfo['start_offset']] = fileinfo
        fullpath = fileinfo['domain'] + '-' + fileinfo['filename']
        id = hashlib.sha1(fullpath)
        mbdx[fileinfo['start_offset']] = id.hexdigest()

    return mbdb

def modestr(val):
    def mode(val):
        if (val & 0x4): r = 'r'
        else: r = '-'
        if (val & 0x2): w = 'w'
        else: w = '-'
        if (val & 0x1): x = 'x'
        else: x = '-'
        return r+w+x
    return mode(val>>6) + mode((val>>3)) + mode(val)

def fileinfo_str(f, verbose=False):
    if not verbose: return "(%s)%s::%s %s" % (f['fileID'], f['domain'], f['filename'], f['start_offset'])
    if (f['mode'] & 0xE000) == 0xA000: type = 'l' # symlink
    elif (f['mode'] & 0xE000) == 0x8000: type = '-' # file
    elif (f['mode'] & 0xE000) == 0x4000: type = 'd' # dir
    else: 
        print >> sys.stderr, "Unknown file type %04x for %s" % (f['mode'], fileinfo_str(f, False))
        type = '?' # unknown
    info = ("%s%s %08x %08x %7d %10d %10d %10d (%s)%s::%s" % 
            (type, modestr(f['mode']&0x0FFF) , f['userid'], f['groupid'], f['filelen'], 
             f['mtime'], f['atime'], f['ctime'], f['fileID'], f['domain'], f['filename']))
    if type == 'l': info = info + ' -> ' + f['linktarget'] # symlink destination
    for name, value in f['properties'].items(): # extra properties
        info = info + ' ' + name + '=' + repr(value)
    return info
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
 	
	    	
	    	
	    	
	    	
	    	
	    	
	    	
	    	
	    	
	    	
	    	
	    	
	    	

if __name__ == '__main__':
	
	# change to iTunes backup directory, wherever that may be
	os.chdir( os.path.expanduser(workingDir[ platform.system() ] ) )
	
	print os.getcwd()
	
	buildiPhoneImageDigestBank()   
		
	if not safeMode:
		try:
			os.stat( outputDir )
		except:
			os.makedirs( outputDir )
	
	top = os.getcwd();
	
	for root, subFolders, files in os.walk( "." ):
		for ff in files:
			if re.match(ur"((?!Snapshot).)*$", root):  #ignore snapshot directories
				if re.match(ur"^Manifest\.mbdb$", ff):
					print " ^-^ " + root + "\\" + ff
					backupFromDatabase(os.path.join(root, ff))
		if re.match(ur"((?!Extract).)*$", root ) and root != ".":# we don't check our extracted folder, or current folder
			print " ^-^ " + root
			extractMediaFromSpoofedHashes( root )	

					
					
	for domain in sorted(sizes, key=sizes.get):
		if( sizes[domain] > 1024 * 1024 ):
			print "%-60s : (%dMB)" % (domain, int(sizes[domain]/1024/1024))


























"""
File notes
SMS / Text messages	1-6	sms.db	3d0d7e5fb2ce288813306e4d4636395e047a3d28	SQLite 3
Contacts / address book	2-6	AddressBook.sqlitedb	31bb7ba8914766d4ba40d6dfb6113c8b614be442	SQLite 3
Calendar	2-6	Calendar.sqlitedb	2041457d5fe04d39d0ab481178355df6781e6858	SQLite 3
Notes	4-6	notes.sqlite	ca3bc056d4da0bbf88b5fb3be254f3b7147e639c	SQLite 3
Call history	4-6	call_history.db	2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca	SQLite 3
Locations	4 - 6	consolidated.db	4096c9ec676f2847dc283405900e284a7c815836	SQLite 3
dsfdasf 12b144c0bd44f2b3dffd9186d3f9c05b917cee25  lkjsadflkjasdf iPhoto
adsfasdf b03b6432c8e753323429e15bc9ec0a8040763424 lkjsdf iPhoto backup

photos, SMS, call log and contacts
"""					
					