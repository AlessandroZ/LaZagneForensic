#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.dpapi import Decrypt_DPAPI
from lazagne.config.utils import build_path
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import traceback
import re
import os

class Wifi(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'Wifi', 'wifi', system_module=True)
	
	def run(self, software_name=None):
		path = build_path(software_name)
		if path:
			pwdFound = []
			dpapi = constant.user_dpapi if constant.user_dpapi is not None else Decrypt_DPAPI()
			if dpapi:
				for repository in os.listdir(path):
					wifi_dir = os.path.join(path, repository)
					for r, _, xml_files in os.walk(wifi_dir):
						
						for xml_file in xml_files:
							
							values 		= {}
							xml 		= os.path.join(r, xml_file)
							tree 		= ET.ElementTree(file=xml)
							root 		= tree.getroot()
							xmlschema 	= ''

							if '}' in root.tag:
								i 			= root.tag.index('}')
								xmlschema 	= root.tag[:i+1]
						
							name = root.find('{xmlschema}name'.format(xmlschema=xmlschema))
							if name is not None:
								values['Wifi'] = name.text

							authentication = root.find('{xmlschema}MSM/{xmlschema}security/{xmlschema}authEncryption/{xmlschema}authentication'.format(xmlschema=xmlschema))
							if authentication is not None:
								values['Authentication'] = authentication.text

							key_material = root.find('{xmlschema}MSM/{xmlschema}security/{xmlschema}sharedKey/{xmlschema}keyMaterial'.format(xmlschema=xmlschema))
							if key_material is not None:
									wifi_pwd = dpapi.decrypt_wifi_blob(key_material.text)
									values['Password'] = wifi_pwd
									
							if values:
								pwdFound.append(values)
				
				return pwdFound