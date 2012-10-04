#!/usr/bin/env python
import sys
import hashlib
import re
import os
import shutil




"""

This script parses the Manifest.mbdb file which later versions of IOS use to store backup information

It recursively scans for Manifest files,  searches images and extracts them into folder called photos

Run this script in:
OS X:
~/Library/Application Support/MobileSync/Backup
Windows:
%AppData%\Apple Computer\MobileSync\Backup\


This script uses code originally by galloglass on stackoverflow 
User Robert Munafo posted an updated version:
http://stackoverflow.com/questions/3085153/how-to-parse-the-manifest-mbdb-file-in-an-ios-4-0-itunes-backup


"""


mbdx = {}
outputDir = "photos"



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
	
def runIt( file ):

	mbdb = process_mbdb_file( file )
	for offset, fileinfo in mbdb.items():
		if offset in mbdx:
			fileinfo['fileID'] = mbdx[offset]
			if re.match(ur"Media", fileinfo['domain']) and re.match(ur"[^THM]", fileinfo['filename']):
				print "Media!" + " " + fileinfo['filename'] + " " + fileinfo['fileID']# path
				
				target =  os.path.join( os.getcwd(), outputDir)
				for p in fileinfo['filename'].split("/"):
					target = os.path.join( target, p  )					
				print target
				DIR =  os.path.split( target )[0]
				
				try:
					os.stat( DIR )
				except:
					os.makedirs( DIR )
					
				src =  os.path.join(DIR,fileinfo['fileID']) 
				
				try:
					os.stat( src  )
				except:
					try:
						os.stat( target )
					except:
						shutil.copyfile( src,  target )

		else:
			fileinfo['fileID'] = "<nofileID>"
			print >> sys.stderr, "No fileID found for %s" % fileinfo_str(fileinfo)
			print fileinfo_str(fileinfo,True)
			
	

if __name__ == '__main__':



	top = os.getcwd();
	
	
	
	try:
		os.stat( outputDir )
	except:
		os.makedirs( outputDir )
	
	
	
	
	for root, subFolders, files in os.walk( "." ):
		for ff in files:
			if re.match(ur"((?!shot).)*$", root):  #ignore snapshot directories
				if re.match(ur"^Manifest\.mbdb$", ff):
					runIt(os.path.join(root, ff))
					print "^-^" + root + "\\" + ff
					
					
					
					
					