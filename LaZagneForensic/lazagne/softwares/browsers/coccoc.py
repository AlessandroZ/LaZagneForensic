#!/usr/bin/env python
# -*- coding: utf-8 -*-
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import traceback
import sqlite3
import os

class CocCoc(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, name='coccoc', category='browsers', dpapi_used=True)

	def run(self, software_name=None):
		path = build_path(software_name)
		if path:
			pwdFound = []
			for profile in os.listdir(path):
				database_path = os.path.join(path, profile, u'Login Data')
				if not os.path.exists(database_path):
					continue

				# Connect to the Database
				try:
					conn 	= sqlite3.connect(database_path)
					cursor 	= conn.cursor()
				except Exception,e:
					print_debug('ERROR', u'An error occured opening the database file')
					print_debug('DEBUG', traceback.format_exc())
					continue 
				
				# Get the results
				cursor.execute('SELECT action_url, username_value, password_value FROM logins')
				for result in cursor.fetchall():
					try:
						# Decrypt the Password
						password = constant.user_dpapi.decrypt_blob(result[2])
						if password:
							pwdFound.append(
								{
									'URL'		: result[0], 
									'Login'		: result[1], 
									'Password'	: password
								}
							)
					except Exception,e:
						print_debug('DEBUG', traceback.format_exc())
				
				conn.close()

			return pwdFound
