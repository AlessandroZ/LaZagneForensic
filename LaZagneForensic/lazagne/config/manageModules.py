#!/usr/bin/env python
# -*- coding: utf-8 -*- 

# browsers
from lazagne.softwares.browsers.mozilla import Mozilla
from lazagne.softwares.browsers.chrome import Chrome
from lazagne.softwares.browsers.coccoc import CocCoc
from lazagne.softwares.browsers.opera import Opera

# chats
from lazagne.softwares.chats.pidgin import Pidgin

# databases
from lazagne.softwares.databases.dbvis import Dbvisualizer
from lazagne.softwares.databases.robomongo import Robomongo
from lazagne.softwares.databases.sqldeveloper import SQLDeveloper
from lazagne.softwares.databases.squirrel import Squirrel

# sysadmin
from lazagne.softwares.sysadmin.apachedirectorystudio import ApacheDirectoryStudio
from lazagne.softwares.sysadmin.filezilla import Filezilla
from lazagne.softwares.sysadmin.ftpnavigator import FtpNavigator
from lazagne.softwares.sysadmin.unattended import Unattended

# svn
from lazagne.softwares.svn.tortoise import Tortoise

# wifi
from lazagne.softwares.wifi.wifi import Wifi

# windows
from lazagne.softwares.windows.credman import Credman
from lazagne.softwares.windows.vault import Vault
from lazagne.softwares.windows.cachedump import Cachedump
from lazagne.softwares.windows.hashdump import Hashdump
from lazagne.softwares.windows.lsa_secrets import LSASecrets
from lazagne.softwares.windows.systemvault import Sysvault
from lazagne.softwares.windows.windows_password import WindowsPassword


def get_categories():
	category = {
		'browsers'	: {'help': 'Web browsers supported'},
		'chats'		: {'help': 'Chat clients supported'},
		'databases'	: {'help': 'SQL/NoSQL clients supported'},
		'mails'		: {'help': 'Email clients supported'},
		'svn'		: {'help': 'SVN clients supported'},
		'sysadmin'	: {'help': 'SCP/SSH/FTP/FTPS clients supported'},
		'windows'	: {'help': 'Windows credentials (credential manager, etc.)'},
		'wifi'		: {'help': 'Wifi'},
	}
	return category
	
def get_modules():
	moduleNames = [
		# Browser
		Chrome(), 
		Mozilla(),
		Opera(),
		CocCoc(),

		# Chats
		Pidgin(),	

		# Databases
		Dbvisualizer(), 
		Robomongo(),
		SQLDeveloper(),
		Squirrel(),

		# SVN
		Tortoise(),

		# Sysadmin
		ApacheDirectoryStudio(),
		Filezilla(),
		FtpNavigator(), 
		Unattended(),

		# Wifi
		Wifi(),

		# Windows
		Cachedump(),
		Credman(),
		Vault(),
		Hashdump(),
		LSASecrets(), 
		Sysvault(),
		WindowsPassword(),
	]
	return moduleNames
