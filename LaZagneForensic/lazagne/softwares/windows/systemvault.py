#!/usr/bin/env python
# -*- coding: utf-8 -*- s
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.dpapi import Decrypt_DPAPI
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import traceback

class Sysvault(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'sysvault', 'windows', system_module=True)

	def run(self, software_name=None):
		pwdFound = []

		vaults_directory = build_path('Vault_system')
		if vaults_directory:
			dpapi = constant.user_dpapi if constant.user_dpapi is not None else Decrypt_DPAPI()
			if dpapi:
				for vault_directory in os.listdir(vaults_directory):
					vault_directory = os.path.join(vaults_directory, vault_directory)
					try:
						result = dpapi.decrypt_system_vault(vault_directory)
						if result:
							pwdFound += result
					except:
						print_debug('DEBUG', traceback.format_exc())

		return pwdFound