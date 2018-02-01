#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from creddump7.win32.lsasecrets import get_file_secrets
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import os

class LSASecrets(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'lsasecrets', 'windows', system_module=True)		

	def run(self, software_name=None):
		pwdFound = []
		
		path = build_path('Hives')
		if path:
			system 		= os.path.join(path, 'SYSTEM')
			security 	= os.path.join(path, 'SECURITY')
			
			if os.path.exists(system) and os.path.exists(security):
				if os.path.isfile(system) and os.path.isfile(security):
					secrets = get_file_secrets(system, security, True)
					if secrets:
						pwdFound = ['__LSASecrets__', secrets]
					
		return pwdFound
