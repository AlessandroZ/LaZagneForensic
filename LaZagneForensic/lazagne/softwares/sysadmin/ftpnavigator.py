#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import struct
import os

class FtpNavigator(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'ftpnavigator', 'sysadmin', system_module=True)

	def decode(self, encode_password):
		password = ''
		for p in encode_password:
			password += chr(struct.unpack('B', p)[0] ^ 0x19)
		return password		
		
	def run(self, software_name=None):
		path = build_path(software_name)
		if path:
			filepath = os.path.join(path, u'Ftplist.txt')
			if os.path.exists(filepath):
				f = open(filepath, 'r')
				pwdFound = []
				for ff in f.readlines():
					values = {}
					info = ff.split(';')
					for i in info:
						i = i.split('=')
						if i[0] == 'Name':
							values['Name'] = i[1]
						if i[0] == 'Server':
							values['Host'] =  i[1]
						if i[0] == 'Port':
							values['Port'] =  i[1]
						if i[0] == 'User':
							values['Login'] = i[1]
						if i[0] == "Password":
							if i[1] != '1' and i[1] != '0':
								values['Password'] = self.decode(i[1])
					
					# used to save the password if it is an anonymous authentication
					if values['Login'] == 'anonymous' and 'Password' not in values.keys():
						values['Password'] = 'anonymous'
					
					pwdFound.append(values)
				
				return pwdFound

