#!/usr/bin/env python
# -*- coding: utf-8 -*- s
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import traceback

class Vault(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'vault', 'windows', dpapi_used=True)

	def run(self, software_name=None):
		pwdFound = []

		path = build_path('DPAPI')
		if path:
			vaults_directory = os.path.join(path, u'Local', u'Vault')
			if os.path.exists(vaults_directory):
				for vault_directory in os.listdir(vaults_directory):
					vault_directory = os.path.join(vaults_directory, vault_directory)
					try:
						result = constant.user_dpapi.decrypt_vault(vault_directory)
						if result:
							pwdFound += result
					except:
						print_debug('DEBUG', traceback.format_exc())

		return pwdFound