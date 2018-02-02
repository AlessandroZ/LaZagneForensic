#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""TODO."""

from Crypto.Cipher import AES
from lazagne.config.modules.DPAPI.Core import blob
from lazagne.config.modules.DPAPI.Core import masterkey
from lazagne.config.modules.DPAPI.Core import registry
import vaultschema
import vaultstruct
import construct
import optparse
import os
import sys

def decrypt_blob(mkp, blob):
	"""Helper to decrypt blobs."""
	mks = mkp.getMasterKeys(blob.mkguid)
	if mks:
		for mk in mks:
			if mk.decrypted:
				blob.decrypt(mk.get_key())
				if blob.decrypted:
					break
	else:
		return False, 'MasterKey not found for blob.'

	if blob.decrypted:
		return True, blob.cleartext
	
	return False, ''

	
def decrypt_vault_attribute(vault_attr, key_aes128, key_aes256):
	"""Helper to decrypt VAULT attributes."""
	if not vault_attr.size:
		return '', False

	if vault_attr.has_iv:
		cipher = AES.new(key_aes256, AES.MODE_CBC, vault_attr.iv)
		is_attribute_ex = True
	else:
		cipher = AES.new(key_aes128, AES.MODE_CBC)
		is_attribute_ex = False

	return cipher.decrypt(vault_attr.data), is_attribute_ex


def get_vault_schema(guid, base_dir, default_schema):
	'''Helper to get the Vault schema to apply on decoded data.'''
	vault_schema = default_schema
	schema_file_path = os.path.join(base_dir, guid + '.vsch')
	try:
		with open(schema_file_path, 'rb') as fschema:
			vsch = vaultschema.VAULT_VSCH.parse(fschema.read())
			vault_schema = vaultschema.vault_schemas.get(
				vsch.schema_name.data,
				vaultschema.VAULT_SCHEMA_GENERIC)
	except IOError:
		pass
	return vault_schema

def decrypt_vault(mkp=None, vaults_dir=None):
	vpol_filename = os.path.join(os.path.sep, vaults_dir, 'Policy.vpol')
	if not os.path.exists(vpol_filename):
		return False, 'Policy file not found: {file}'.format(file=vpol_filename)

	with open(vpol_filename, 'rb') as fin:
		vpol = vaultstruct.VAULT_POL.parse(fin.read())

	vpol_blob = blob.DPAPIBlob(vpol.vpol_store.blob_store.raw)

	ok, vpol_decrypted = decrypt_blob(mkp, vpol_blob)
	if not ok:
		return False, 'Unable to decrypt blob. {message}'.format(message=vpol_decrypted)

	vpol_keys = vaultstruct.VAULT_POL_KEYS.parse(vpol_decrypted)

	key_aes128 = vpol_keys.vpol_key1.bcrypt_blob.key
	key_aes256 = vpol_keys.vpol_key2.bcrypt_blob.key
	
	pwdFound = []
	for file in os.listdir(vaults_dir):
		if file.lower().endswith('.vcrd'):
			filepath = os.path.join(vaults_dir, file)
			attributes_data = {}
			with open(filepath, 'rb') as fin:
				vcrd = vaultstruct.VAULT_VCRD.parse(fin.read())

				current_vault_schema = get_vault_schema(
					vcrd.schema_guid,
					vaults_dir,
					vaultschema.VAULT_SCHEMA_GENERIC)
				
				for attribute in vcrd.attributes:
					decrypted, is_attribute_ex = decrypt_vault_attribute(attribute.VAULT_ATTRIBUTE, key_aes128, key_aes256)
					if is_attribute_ex:
						schema = current_vault_schema
					else:
						schema = vaultschema.VAULT_SCHEMA_SIMPLE

					attributes_data[attribute.VAULT_ATTRIBUTE.id] = {
						'data': decrypted,
						'schema': schema
					}

				attributes_data[0xDEAD0000 + vcrd.extra_entry.id] = {
					'data': str(vcrd.extra_entry.data),
					'schema': vaultschema.VAULT_SCHEMA_SIMPLE
				}

			# parse value found
			for k, v in sorted(attributes_data.iteritems()):
				dataout = v['schema'].parse(v['data'])
				creds_tuple = []
				if 'Container' in str(type(dataout)):
					for item in dataout['VAULT_ATTRIBUTE_ITEM']:
						if item['id'] != 100:
							creds_tuple.append((item['id'], item['item']['data']))

				creds = sorted(creds_tuple, key=lambda creds: creds[0])
				if creds:
					values = {}
					if len(creds) == 3:
						values = {
									'URL' 		: creds[0][1],
									'Login' 	: creds[1][1],
									'Password' 	: creds[2][1],
									'File'		: filepath,
								}
					else:
						for cred in creds:
							values['Item_{id}'.format(id=cred[0])] = cred[1]
						values['File'] = filepath
					
					pwdFound.append(values)

	return True, pwdFound