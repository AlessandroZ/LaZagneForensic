# -*- coding: utf-8 -*-
from lazagne.config.write_output import print_debug
from constant import constant
import os

def build_path(software_name):
	path = constant.softwares_path[software_name.capitalize()][constant.dump].format(root=constant.root_dump, user=constant.username)	
	if os.path.exists(path):
		return path
	else:
		print_debug('INFO', u'{software_name} not found.'.format(software_name=software_name))
		return False
