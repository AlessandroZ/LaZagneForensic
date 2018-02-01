#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from creddump7.win32.hashdump import dump_file_hashes
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import os

class Hashdump(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'hashes', 'windows', system_module=True)
		
	def run(self, software_name=None):
		pwdFound = []
		
		path = build_path('Hives')
		if path:
			system 	= os.path.join(path, 'SYSTEM')
			sam 	= os.path.join(path, 'SAM')
			
			if os.path.exists(system) and os.path.exists(sam):
				hashes = dump_file_hashes(system, sam)
				if hashes:
					pwdFound = ['__Hashdump__', hashes]

		return pwdFound
