iPhoneBup - a iPhone backup media extractor written in Python by Nathan Trujillo github.com/bo01ean

What it does:
	This script recursively scans your backup directories,  searches for media and extracts them into folder of the users choosing.
	It uses iPhone's Manifest.mbdb file which later versions of IOS use to store backup information.
	It also uses a spoofed hash list to backup media files.

Why did you write this:
	After upgrading my iPhone a few days ago, I lost my backup after iTunes forgot to create a Manifest file for it.
	Since the files were still on disk, though obfuscated, I knew there was a way to get them back, and this script will do it for you.

Warning:
	I am not responsible if this script kicks your dog, scratches your new car or deletes your files. Please use at your own risk.

To Use:
	1. Check it out from git: https://github.com/bo01ean/iphone-tools.git.
	2. be sure python is installed and in your path.
	3. run this script from the command line and this script should do the rest, auto-magically.

Notes:	
	the safeMode flag makes no changes to the filesystem, only flip to False if you are completely sure!
	this script does not backup app data since there are naming convention issues


This script uses code by galloglass on stackoverflow 
User Robert Munafo posted an updated version:
http://stackoverflow.com/questions/3085153/how-to-parse-the-manifest-mbdb-file-in-an-ios-4-0-itunes-backup
