#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import base64
import os 

class Tortoise(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'tortoise', 'svn', dpapi_used=True)

	def run(self, software_name=None):	
		path = build_path(software_name)
		if path:
			pwdFound = []
			for root, dirs, files in os.walk(path):
				for name_file in files:
					f = open(os.path.join(path, name_file), 'r')
					
					url 		= ''
					username 	= ''
					result 		= ''
					
					i = 0
					# password
					for line in f:
						if i == -1:
							result = line.replace('\n', '')
							break
						if line.startswith('password'):
							i = -3
						i+=1
					
					i = 0
					# url
					for line in f:
						if i == -1:
							url = line.replace('\n', '')
							break
						if line.startswith('svn:realmstring'):
							i = -3
						i+=1

					i = 0
					
					# username
					for line in f:
						if i == -1:
							username = line.replace('\n', '')
							break
						if line.startswith('username'):
							i = -3
						i+=1
					
					# encrypted the password
					if result:
						try:
							password = constant.user_dpapi.decrypt_blob(base64.b64decode(result))
							pwdFound.append(
								{
									'URL'		: 	url, 
									'Login'		: 	username, 
									'Password'	: 	str(password)
								}
							)
						except:
							pass
			return pwdFound