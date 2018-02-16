#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import os

class Credman(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'credentials', 'windows', dpapi_used=True)
	
	# FOR XP
	# 	entropy = 'abe2869f-9b47-4cd9-a358-c22904dba7f7\0' # FOR CRED_TYPE_GENERIC
	# 	entropy = '82BD0E67-9FEA-4748-8672-D5EFE5B779B0\0' # FOR CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
	
	def run(self, software_name=None):
		pwdFound = []
		path = build_path('DPAPI')
		if path:
			creds_directory = os.path.join(path, u'Roaming', u'Credentials')
			if os.path.exists(creds_directory):
				for cred_file in os.listdir(creds_directory):
					cred = constant.user_dpapi.decrypt_cred(os.path.join(creds_directory, cred_file))
					if cred:
						pwdFound.append(cred)
		
		return pwdFound
