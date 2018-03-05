#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
	- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
	- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

from Registry import Registry
from structures import *
import crypto

class Regedit(object):
	"""
	This class provides several functions to handle registry extraction	stuff.
	"""

	def __init__(self):
		self.syskey 		= None
		self.lsakeys 		= None
		self.policy 		= 0

	def get_syskey(self, system):
		"""
		Returns the syskey value after decryption from the registry values.
		system argument is the full path to the SYSTEM registry file (usually located under %WINDIR%\\system32\\config\\ directory.
		"""
		with open(system, 'rb') as f:
			r = Registry.Registry(f)
		
		cs 			= r.open('Select').value('Current').value()
		r2 			= r.open('ControlSet%03d\\Control\\Lsa' % cs)
		syskey 		= ''.join([r2.subkey(x)._nkrecord.classname() for x in ('JD', 'Skew1', 'GBG', 'Data')])
		syskey 		= syskey.encode('ascii').decode('hex')
		transforms 	= [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
		
		skey = ''
		for i in xrange(len(syskey)):
			skey += syskey[transforms[i]]
		return skey

	def get_lsa_key(self, security):
		"""
		Returns and decrypts the LSA secret key for 'CurrentControlSet'.
		It is stored under Policy\\PolSecretEncryptionKey.
		security is the full path the the SECURITY registry file (usually located under %WINDIR%\\system32\\config\\ directory.
		To decrypt the LSA key, syskey is required. Thus you must first call self.get_syskey() if it has not been previously done.
		"""
		lsakey = ''
		if self.syskey:
			with open(security, 'rb') as f:
				r = Registry.Registry(f)
			
			polrev 		= r.open('Policy\\PolRevision').value('(default)').value()
			pol 		= POL_REVISION.parse(polrev)
			self.policy = float('%d.%02d' % (pol.major, pol.minor))

			if self.policy > 1.09:
				# NT6
				r2 		= r.open('Policy\\PolEKList')
				lsakey 	= r2.value('(default)').value()
			else:
				# NT5
				r2 		= r.open('Policy\\PolSecretEncryptionKey')
				lsakey 	= r2.value('(default)').value()
		
		rv = None
		if self.policy > 1.09:
			currentKey, self.lsakeys = crypto.decrypt_lsa_key_nt6(lsakey, self.syskey)
			rv = self.lsakeys[currentKey]['key']
		else:
			self.lsakeys = crypto.decrypt_lsa_key_nt5(lsakey, self.syskey)
			rv = self.lsakeys[1]
		return rv

	def get_lsa_secrets(self, security, system):
		"""
		Retrieves and decrypts LSA secrets from the registry.
		security and system arguments are the full path to the corresponding registry files.
		This function automatically calls self.get_syskey() and self.get_lsa_key() functions prior to the secrets retrieval.

		Returns a dictionary of secrets.
		"""
		self.syskey = self.get_syskey(system)
		currentKey 	= self.get_lsa_key(security)
		lsa_secrets = {}
		
		with open(security, 'rb') as f:
			r = Registry.Registry(f)
		
		r2 = r.open('Policy\\Secrets')
		for i in r2.subkeys():
			lsa_secrets[i.name()] = {}
			for j in i.subkeys():
				lsa_secrets[i.name()][j.name()] = j.value('(default)').value()
		
		for k, v in lsa_secrets.iteritems():
			for s in ['CurrVal', 'OldVal']:
				if v[s] != '':
					if self.policy > 1.09:
						# NT6
						lsa_secrets[k][s] = crypto.decrypt_lsa_secret(v[s], self.lsakeys)
					else:
						lsa_secrets[k][s] = crypto.SystemFunction005(v[s][0xc:], currentKey)
			
			for s in ['OupdTime', 'CupdTime']:
				if lsa_secrets[k][s] > 0:
					lsa_secrets[k][s] = SYSTEM_TIME.parse(lsa_secrets[k][s]).time

		return lsa_secrets
