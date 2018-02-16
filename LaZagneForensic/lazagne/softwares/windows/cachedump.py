#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from creddump7.win32.domcachedump import dump_file_hashes
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import os

class Cachedump(ModuleInfo):
	def __init__(self):	
		ModuleInfo.__init__(self, 'cachedump', 'windows', system_module=True)

	def run(self, software_name=None):
		pwdFound = []
		
		path = build_path('Hives')
		if path:
			system 		= os.path.join(path, 'SYSTEM')
			security 	= os.path.join(path, 'SECURITY')
			
			if os.path.exists(system) and os.path.exists(security):
				if os.path.isfile(system) and os.path.isfile(security):
					hashes = dump_file_hashes(system, security, True)
					if hashes:
						pwdFound = ['__MSCache__', hashes]

		return pwdFound
