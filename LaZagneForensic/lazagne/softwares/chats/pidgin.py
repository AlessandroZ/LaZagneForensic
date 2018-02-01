#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import os

class Pidgin(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, name='pidgin', category='chats')

	def run(self, software_name=None):		
		path = build_path(software_name)
		if path:
			account_file = os.path.join(path, u'accounts.xml')
			if os.path.exists(account_file):
				tree 		= ET.ElementTree(file=account_file)
				root 		= tree.getroot()
				pwdFound 	= []

				for account in root.findall('account'):
					if account.find('name') is not None:
						name 		= account.find('name')
						password 	= account.find('password')

						if name is not None and password is not None:
							pwdFound.append(
												{
													'Login'		: name.text, 
													'Password'	: password.text
												}
											)
				return pwdFound
