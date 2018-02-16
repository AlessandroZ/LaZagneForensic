#!/usr/bin/env python
# -*- coding: utf-8 -*- s

# Thanks to Jean-Christophe Delaunay and Jiss/Fist0urs from Synacktiv
# Check their work: 
# - https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/run/DPAPImk2john.py
# - https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf

from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *

class DPAPIHash(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'DPAPIHash', 'windows')

	def get_hash(self, context):
		constant.user_dpapi.get_DPAPI_hash(context=context)
		if constant.dpapi_hash:
			h = {
					'DPAPI_Hash_{context}'.format(context=context.capitalize()) : constant.dpapi_hash
				}
			constant.dpapi_hash = None
			return  h
		else:
			return False

	def run(self, software_name=None):
		pwdFound = []

		if constant.user_dpapi:
			for context in ['local', 'domain']:
				h = self.get_hash(context)
				if h:
					pwdFound.append(h)

		return pwdFound