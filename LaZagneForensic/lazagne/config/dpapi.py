#!/usr/bin/python
# -*- coding: utf-8 -*- 
from lazagne.config.modules.blobdec import decrypt_encrypted_blob
from lazagne.config.modules.preferred import display_masterkey
from lazagne.config.modules.creddec import decrypt_user_cred
from lazagne.config.modules.vaultdec import decrypt_vault
from lazagne.config.write_output import print_debug
from lazagne.config.utils import build_path
from lazagne.config.constant import *
from lazagne.config.modules.DPAPI.Core import masterkey
from lazagne.config.modules.DPAPI.Core import registry
from lazagne.config.modules.DPAPI.Core import blob
from modules.creddec import *
import traceback
import os

class Decrypt_DPAPI():
	def __init__(self, password=None, pwdhash=None):
		self.sid 					= None
		self.preferred_umkp 		= None
		self.dpapi_ok 				= False
		self.umkp 					= None
		self.smkp 					= None
		self.last_masterkey_file	= None
		adding_missing_path 		= u''
		
		# -------------------------- User Information --------------------------

		path = build_path('DPAPI')
		if constant.dump == 'local':
			adding_missing_path 	= u'/Microsoft'

		if path:
			protect_folder = os.path.join(path, u'Roaming{path}/Protect'.format(path=adding_missing_path))
			if os.path.exists(protect_folder):
				for folder in os.listdir(protect_folder):
					if folder.startswith('S-'):
						self.sid = folder

				masterkeydir 	= os.path.join(protect_folder, self.sid)
				if os.path.exists(masterkeydir):
					# user master key pool
					self.umkp = masterkey.MasterKeyPool()
					
					# load all master key files (not only the one contained on preferred)
					self.umkp.loadDirectory(masterkeydir)

					preferred_file = os.path.join(masterkeydir, 'Preferred')
					if os.path.exists(preferred_file):
						preferred_mk_guid 	= display_masterkey(open(preferred_file, 'rb'))
						
						# Preferred file contains the GUID of the last mastekey created
						self.last_masterkey_file	= os.path.join(masterkeydir, preferred_mk_guid)
						
						# Be sure the preferred mk guid exists, otherwise take the one which have a similar name (sometimes an error occured retreiving the guid)
						if not os.path.exists(self.last_masterkey_file):
							for folder in os.listdir(masterkeydir):
								if folder.startswith(preferred_mk_guid[:6]):
									self.last_masterkey_file = os.path.join(masterkeydir, folder)

						if os.path.exists(self.last_masterkey_file):
							print_debug('DEBUG', u'Last masterkey created: {masterkefile}'.format(masterkefile=self.last_masterkey_file))
							self.preferred_umkp = masterkey.MasterKeyPool()
							self.preferred_umkp.addMasterKey(open(self.last_masterkey_file, 'rb').read())

					credhist_path 	= os.path.join(path, 'Roaming{path}/Protect/CREDHIST'.format(path=adding_missing_path))
					credhist		= credhist_path if os.path.exists(credhist_path) else None
					
					if credhist:
						self.umkp.addCredhistFile(self.sid, credhist)
					
					if password:
						if self.umkp.try_credential(self.sid, str(password)):
							self.dpapi_ok = True
						else:
							print_debug('DEBUG', u'Password not correct: {password}'.format(password=password))

					elif pwdhash:
						if self.umkp.try_credential_hash(self.sid, pwdhash.decode('hex')):
							self.dpapi_ok = True
						else:
							print_debug('DEBUG', u'Hash not correct: {pwdhash}'.format(pwdhash=pwdhash))

		# -------------------------- System Information --------------------------

		path = build_path('Hives')
		if path:
			system 		= os.path.join(path, 'SYSTEM')
			security 	= os.path.join(path, 'SECURITY')
			
			if os.path.exists(system) and os.path.exists(security):
				if os.path.isfile(system) and os.path.isfile(security):
					reg 			= registry.Regedit()
					secrets 		= None
					try:
						secrets 		= reg.get_lsa_secrets(security, system)
					except:
						print_debug('DEBUG', traceback.format_exc())

					if secrets:
						dpapi_system 	= secrets.get('DPAPI_SYSTEM')["CurrVal"]
						path 	= build_path('Dpapi_System')
						if path: 
							masterkeydir = os.path.join(path, 'Protect', 'S-1-5-18', 'User')
							if os.path.exists(masterkeydir):
								self.smkp = masterkey.MasterKeyPool()
								self.smkp.loadDirectory(masterkeydir)
								self.smkp.addSystemCredential(dpapi_system)
								self.smkp.try_credential_hash(None, None)


	def check_credentials(self, passwords):
		# the password is tested if possible only on the last masterkey file created by the system (visible on the preferred file) to avoid false positive
		# if tested on all masterkey files, it could retrieve a password without to be able to decrypt a blob (happenned on my host :))
		if self.preferred_umkp:
			self.umkp = self.preferred_umkp

		if self.umkp:
			for password in passwords:
				print_debug('INFO', u'Check password: {password}'.format(password=password))
				if self.umkp.try_credential(self.sid, password):
					print_debug('INFO', u'User password found: {password}\n'.format(password=password))
					self.dpapi_ok = True
					return password

		return False

	def decrypt_blob(self, encrypted_password):
		if self.dpapi_ok:
			ok, msg = decrypt_encrypted_blob(self.umkp, encrypted_password)
			if ok: 
				return msg
			else:
				print_debug('DEBUG', u'{msg}'.format(msg=msg))
		else:
			print_debug('INFO', u'Passwords have not been retrieved. User password seems to be wrong ')
		
		return False

	def decrypt_cred(self, cred_file):
		if self.dpapi_ok:
			ok, msg = decrypt_user_cred(umkp=self.umkp, cred_file=cred_file)
			if ok: 
				return msg
			else:
				print_debug('DEBUG', u'{msg}'.format(msg=msg))
		else:
			print_debug('INFO', u'Passwords have not been retrieved. User password seems to be wrong ')
		
		return False
		
	def decrypt_vault(self, vaults_dir):
		if self.dpapi_ok:
			ok, msg = decrypt_vault(self.umkp, vaults_dir=vaults_dir)
			if ok: 
				return msg
			else:
				print_debug('DEBUG', u'File: {file}\n{msg}'.format(file=vaults_dir, msg=msg))
		else:
			print_debug('INFO', u'Passwords have not been retrieved. User password seems to be wrong ')
		
		return False

	def get_DPAPI_hash(self, context='local'):
		if self.umkp and self.last_masterkey_file:
			self.umkp.get_john_hash(masterkeyfile=self.last_masterkey_file, sid=self.sid, context=context)

	def decrypt_wifi_blob(self, key_material):
		if self.smkp:
			wblob 			= blob.DPAPIBlob(key_material.decode('hex'))
			mks 			= self.smkp.getMasterKeys(wblob.mkguid)

			for mk in mks:
				if mk.decrypted:
					wblob.decrypt(mk.get_key())
					if wblob.decrypted:
						return wblob.cleartext

		return '<not decrypted>'

	def decrypt_system_vault(self, vaults_dir):
		if self.smkp:
			ok, msg = decrypt_vault(self.smkp, vaults_dir=vaults_dir)
			if ok:
				return msg
			else:
				print_debug('DEBUG', u'File: {file}\n{msg}\n'.format(file=vaults_dir, msg=msg))
		else:
			print_debug('INFO', u'Passwords have not been retrieved. User password seems to be wrong ')
		
		return False
