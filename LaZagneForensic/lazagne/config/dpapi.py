#!/usr/bin/python
# -*- coding: utf-8 -*- 

from lazagne.config.DPAPI.masterkey import *
from lazagne.config.DPAPI.registry import *
from lazagne.config.DPAPI.credfile import *
from lazagne.config.DPAPI.vault import *
from lazagne.config.DPAPI.blob import *

from lazagne.config.write_output import print_debug
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import traceback
import os

class Decrypt_DPAPI():
	def __init__(self, password=None, pwdhash=None):
		self.sid 				= None
		self.umkp 				= None
		self.smkp 				= None
		adding_missing_path 	= u''
		
		# User Information

		path = build_path('DPAPI')
		if constant.dump == 'local':
			adding_missing_path = u'/Microsoft'

		if path:
			protect_folder 	= os.path.join(path, u'Roaming{path}/Protect'.format(path=adding_missing_path))
			credhist_file 	= os.path.join(path, u'Roaming{path}/Protect/CREDHIST'.format(path=adding_missing_path))
			
			if os.path.exists(protect_folder):
				for folder in os.listdir(protect_folder):
					if folder.startswith('S-'):
						self.sid = folder
						break
				
				if self.sid:
					masterkeydir = os.path.join(protect_folder, self.sid)
					if os.path.exists(masterkeydir):
						self.umkp = MasterKeyPool()
						self.umkp.load_directory(masterkeydir)
						self.umkp.add_credhist_file(sid=self.sid, credfile=credhist_file)
						
						if password:
							for r in self.umkp.try_credential(sid=self.sid, password=password):
								print_debug('INFO', r)

						elif pwdhash:
							for r in self.umkp.try_credential_hash(self.sid, pwdhash=pwdhash.decode('hex')):
								print_debug('INFO', r)

		# System Information

		path = build_path('Hives')
		if path:
			system 	 = os.path.join(path, 'SYSTEM')
			security = os.path.join(path, 'SECURITY')
			
			if os.path.exists(system) and os.path.exists(security):
				if os.path.isfile(system) and os.path.isfile(security):
					reg 	= Regedit()
					secrets = reg.get_lsa_secrets(security, system)

					if secrets:
						dpapi_system 	= secrets.get('DPAPI_SYSTEM')["CurrVal"]
						path 			= build_path('Dpapi_System')
						if path: 
							masterkeydir = os.path.join(path, u'Protect', u'S-1-5-18', u'User')
							if os.path.exists(masterkeydir):
								self.smkp = MasterKeyPool()
								self.smkp.load_directory(masterkeydir)
								self.smkp.add_system_credential(dpapi_system)
								for r in self.smkp.try_system_credential():
									print_debug('INFO', r)

	def check_credentials(self, passwords):
		if self.umkp:
			for password in passwords:
				for r in self.umkp.try_credential(sid=self.sid, password=password):
					print_debug('INFO', r)

	def manage_response(self, ok, msg):
		if ok:
			return msg
		else:
			print_debug('DEBUG', u'{msg}'.format(msg=msg))
			return False

	def decrypt_blob(self, dpapi_blob):
		"""
		Decrypt DPAPI Blob
		"""
		if self.umkp:
			blob  	= DPAPIBlob(dpapi_blob)
			ok, msg = blob.decrypt_encrypted_blob(mkp=self.umkp)
			return self.manage_response(ok, msg)
		
	def decrypt_cred(self, credfile):
		""" 
		Decrypt Credential Files
		"""
		if self.umkp:
			c = CredFile(credfile)
			ok, msg = c.decrypt(self.umkp)
			return self.manage_response(ok, msg)
		
	def decrypt_vault(self, vaults_dir):
		""" 
		Decrypt Vault Files
		"""
		if self.umkp:
			v = Vault(vaults_dir=vaults_dir)
			ok, msg = v.decrypt(mkp=self.umkp)
			return self.manage_response(ok, msg)

	def get_dpapi_hash(self, context='local'):
		"""
		Retrieve DPAPI hash to bruteforce it using john or hashcat.
		"""
		if self.umkp:
			return self.umkp.get_dpapi_hash(sid=self.sid)

	def get_cleartext_password(self):
		"""
		Retrieve cleartext password associated to the preferred user maskterkey. 
		This password should represent the windows user password. 
		"""
		if self.umkp:
			return self.umkp.get_cleartext_password()

	def decrypt_wifi_blob(self, key_material):
		"""
		Decrypt wifi password
		"""
		if self.smkp:
			blob 	= DPAPIBlob(key_material.decode('hex'))
			ok, msg = blob.decrypt_encrypted_blob(mkp=self.smkp)
			return self.manage_response(ok, msg)

	def decrypt_system_vault(self, vaults_dir):
		"""
		Decrypt System Vault
		"""
		if self.smkp:
			v = Vault(vaults_dir=vaults_dir)
			ok, msg = v.decrypt(mkp=self.smkp)
			return self.manage_response(ok, msg)

