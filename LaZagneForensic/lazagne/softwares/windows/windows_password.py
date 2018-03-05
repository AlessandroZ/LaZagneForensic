# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
from lazagne.config.dpapi import *

class WindowsPassword(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'windows', 'windows')

	def run(self, software_name=None):
		pwdFound = []
		
		if constant.user_dpapi:
			password = constant.user_dpapi.get_cleartext_password()
			if password:
				pwdFound.append(
					{
						'Login'		: constant.username, 
						'Password'	: password
					}
				)
			else:
				# retrieve dpapi hash used to bruteforce (hash can be retrieved without needed admin privilege)
				# method taken from Jean-Christophe Delaunay - @Fist0urs
				# https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf

				print_debug('INFO', u'Windows passwords not found.\nTry to bruteforce this hash (using john or hashcat) depending on your context (domain environment or not)')
				if constant.user_dpapi:
					for context in ['local', 'domain']:
						pwdFound.append(
							{
								'DPAPI_Hash_{context}'.format(context=context.capitalize()) : constant.user_dpapi.get_dpapi_hash(context=context)
							}
						)

		return pwdFound
