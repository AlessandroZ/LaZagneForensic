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
""" Windows DPAPI BLOB decryption utility."""

from DPAPI.Core import masterkey
from DPAPI.Core import registry
from DPAPI.Core import blob

def decrypt_encrypted_blob(mkp, encrypted_password, entropy_hex=None):
	blob_value  = blob.DPAPIBlob(encrypted_password)
	mks         = mkp.getMasterKeys(blob_value.mkguid)
	
	if not mks:
		return False, 'Unable to find MK for blob {mk_guid}'.format(mk_guid=blob_value.mkguid)

	entropy = None
	if entropy_hex:
		entropy = entropy_hex.decode('hex')

	for mk in mks:
		if mk.decrypted:
			blob_value.decrypt(mk.get_key(), entropy=entropy)
			if blob_value.decrypted:
				return True, blob_value.cleartext
			else:
				return False, 'Unable to decrypt blob'
		else:
			return False, 'Unable to decrypt master key'

