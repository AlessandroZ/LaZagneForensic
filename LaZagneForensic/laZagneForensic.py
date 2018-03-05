#!/usr/bin/python

##############################################################################
#                                                                            #
#                           By Alessandro ZANNI                              #
#                                                                            #
##############################################################################

# Disclaimer: Do Not Use this program for illegal purposes ;)

# Softwares that passwords can be retrieved without needed to be in the user environmment
from lazagne.softwares.browsers.mozilla import Mozilla

# Configuration
from lazagne.config.write_output import parseJsonResultToBuffer, print_debug, StandartOutput
from lazagne.config.dpapi import Decrypt_DPAPI
from lazagne.config.manageModules import get_categories, get_modules
from lazagne.config.constant import *
import traceback
import argparse
import logging
import json
import time
import sys
import os

# Object used to manage the output / write functions (cf write_output file)
constant.st = StandartOutput()

# Tab containing all passwords
stdoutRes = []

category 	= get_categories()
moduleNames = get_modules()

# Define a dictionary for all modules
modules = {}
for categoryName in category:
	modules[categoryName] = {}

# Add all modules to the dictionary
for module in moduleNames:
	modules[module.category][module.options['dest']] = module
modules['mails']['thunderbird'] = Mozilla(True) # For thunderbird (firefox and thunderbird use the same class)

def output():
	if args['output']:
		if os.path.isdir(args['output']):
			constant.folder_name = args['output']
		else:
			print '[!] Specify a directory, not a file !'
			sys.exit()

	if args['write_normal']:
		constant.output = 'txt'
	
	if args['write_json']:
		constant.output = 'json'

	if args['write_all']:
		constant.output = 'all'

	if constant.output:
		if not os.path.exists(constant.folder_name):
			os.makedirs(constant.folder_name)
			# constant.file_name_results = 'credentials' # let the choice of the name to the user
		
		if constant.output != 'json':
			constant.st.write_header()

	# Remove all unecessary variables
	del args['write_normal']
	del args['write_json']
	del args['write_all']

def quiet_mode():
	if args['quiet']:
		constant.quiet_mode = True

def verbosity():
	# Write on the console + debug file
	if   args['verbose'] 	== 0: level = logging.CRITICAL
	elif args['verbose'] 	== 1: level = logging.INFO
	elif args['verbose'] 	>= 2: level = logging.DEBUG
	
	formatter 	= logging.Formatter(fmt="%(message)s")
	stream 		= logging.StreamHandler()
	stream.setFormatter(formatter)
	root = logging.getLogger()
	root.setLevel(level)
	# If other logging are set
	for r in root.handlers:
		r.setLevel(logging.CRITICAL)
	root.addHandler(stream)
	del args['verbose']

def run_module(title, module):
	try:
		constant.st.title_info(title.capitalize()) 					# print title
		pwdFound = module.run(title.capitalize())					# run the module
		constant.st.print_output(title.capitalize(), pwdFound) 		# print the results
		
		# Return value - not used but needed
		yield True, title.capitalize(), pwdFound
	except:
		traceback.print_exc()
		print
		error_message = traceback.format_exc()
		yield False, title.capitalize(), error_message


def launch_module(module, system_module=False):
	modulesToLaunch = []
	try:
		# Launch only a specific module
		for i in args:
			if args[i] and i in module:
				modulesToLaunch.append(i)
	except:
		# If no args
		pass

	# Launch all modules
	if not modulesToLaunch:
		modulesToLaunch = module
	
	for i in modulesToLaunch:

		if system_module ^ module[i].system_module:
			continue

		if module[i].dpapi_used:
			constant.module_to_exec_at_end.append(
				{
					'title'		: i,
					'module' 	: module[i],
				}
			)
			continue

		# run module
		for m in run_module(title=i, module=module[i]):
			yield m

def manage_advanced_options():

	# Jitsi advanced options
	if args.get('master_pwd', None):
		constant.jitsi_masterpass = args['master_pwd']

	if  args.get('remote', None):
		constant.dump 		= 'remote'
		constant.root_dump 	= args['remote']

	if args.get('local', None):
		constant.dump 		= 'local'
		constant.root_dump 	= args['local']

	if args.get('password', None):
		constant.user_password 	= args['password']

	if args.get('pwdhash', None):
		constant.user_pwdhash 	= args['pwdhash']

# Run only one module
def runModule(category_choosed, system_module=False):
	global category
	
	if category_choosed != 'all':
		category = [category_choosed]

	constant.module_to_exec_at_end = []
	for categoryName in category:
		for r in launch_module(modules[categoryName], system_module):
			yield r

	if constant.module_to_exec_at_end:
		if constant.user_dpapi:
			# add username to check username equals passwords
			constant.passwordFound.append(constant.username)
			constant.user_dpapi.check_credentials(constant.passwordFound)

			for module in constant.module_to_exec_at_end:
				for m in run_module(title=module['title'], module=module['module']):
					yield m


# Write output to file (json and txt files)
def write_in_file(result):
	if constant.output == 'json' or constant.output == 'all':
		try:
			# Human readable Json format
			prettyJson = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
			with open(os.path.join(constant.folder_name, constant.file_name_results + '.json'), 'a+b') as f:
				f.write(prettyJson.decode('unicode-escape').encode('UTF-8'))
			constant.st.do_print(u'[+] File written: {file}'.format(file=os.path.join(constant.folder_name, constant.file_name_results + '.json')))
		except Exception as e:
			print_debug('ERROR', u'Error writing the output file: {error}'.format(error=e))

	if constant.output == 'txt' or constant.output == 'all':
		try:
			with open(os.path.join(constant.folder_name, constant.file_name_results + '.txt'), 'a+b') as f:
				f.write(parseJsonResultToBuffer(result).encode("UTF-8"))
			constant.st.write_footer()
			constant.st.do_print(u'[+] File written: {file}'.format(file=os.path.join(constant.folder_name, constant.file_name_results + '.txt')))
		except Exception as e:
			print_debug('ERROR', u'Error writing the output file: {error}'.format(error=e))

# Get user list to retrieve  their passwords
def get_user_list_on_filesystem():
	user_path = os.path.join(constant.root_dump, 'Users')

	if not constant.root_dump or not os.path.exists(user_path):
		print_debug('ERROR', u'Specify a correct path with -remote or -local options')
		return []

	# Check existing users on the system (get only directories)
	all_users = os.listdir(user_path)

	# Remove default users
	for user in ['All Users', 'Default User', 'Default', 'Public', 'desktop.ini']:
		if user in all_users:
			all_users.remove(user)

	return all_users

def runLaZagne(category_choosed='all', password=None, pwdhash=None, dump=None, root_dump=None, quiet_mode=None):

	# These if statement are only useful if other tools call this function
	if dump:
		constant.dump = dump
	if root_dump:
		constant.root_dump = root_dump
	if quiet_mode:
		constant.quiet_mode = quiet_mode

	# Ready to check for all users remaining
	all_users = get_user_list_on_filesystem()
	for user in all_users:
		constant.st.print_user(user)
		
		constant.username  		= user.decode('utf-8')
		constant.finalResults 	= {'User': user}
		yield 'User', user
		
		constant.user_dpapi = Decrypt_DPAPI(password=password, pwdhash=pwdhash)

		for r in runModule(category_choosed, system_module=False):
			yield r
		
		stdoutRes.append(constant.finalResults)

	# System modules (hashdump, lsa secrets, etc.)
	constant.username  		= 'SYSTEM'.decode('utf-8')
	constant.finalResults 	= {'User': constant.username}
	constant.st.print_user(constant.username)
	
	yield 'User', constant.username
	for r in runModule(category_choosed, system_module=True):
		yield r

	stdoutRes.append(constant.finalResults)

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description=constant.st.banner, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('--version', action='version', version='Version ' + str(constant.CURRENT_VERSION), help='laZagne version')

	# ------------------------------------------- Permanent options -------------------------------------------
	# Version and verbosity 
	PPoptional = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	PPoptional._optionals.title = 'optional arguments'
	PPoptional.add_argument('-v', 		dest='verbose', 	action='count', 		default=0, 		help='increase verbosity level')
	PPoptional.add_argument('-quiet', 	dest='quiet', 		action='store_true', 	default=False, 	help='nothing is printed to the output')
	
	# Dump directory 
	PDump = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	PDump._optionals.title = 'Dump directory'
	PDump.add_argument('-remote', 	dest='remote', 			action='store', 		default=False, help='path of the dump done on the remote host')
	PDump.add_argument('-local', 	dest='local', 			action='store', 		default=False, help='path of the mounted drive')

	# Decrypt passwords
	Ppwd = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	Ppwd._optionals.title = 'Needed to decrypt all passwords (by DPAPI)'
	Ppwd.add_argument('-password', 	dest='password', 		action='store', 		default=False, help='Windows user password')
	Ppwd.add_argument('-pwdhash', 	dest='pwdhash',  		action='store', 		default=False, help='Windows user hash (not NTLM hash)')

	# Output 
	PWrite = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	PWrite._optionals.title = 'Output'
	PWrite.add_argument('-oN', 		dest='write_normal', 	action='store_true', 	default=None, 	help='output file in a readable format')
	PWrite.add_argument('-oJ', 		dest='write_json',		action='store_true', 	default=None, 	help='output file in a json format')
	PWrite.add_argument('-oA', 		dest='write_all', 		action='store_true', 	default=None, 	help='output file in all format')
	PWrite.add_argument('-output', 	dest='output', 			action='store', 		default='.', 	help='destination path to store results (default:.)')

	# ------------------------------------------- Add options and suboptions to all modules -------------------------------------------
	all_subparser = []
	for c in category:
		category[c]['parser'] = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
		category[c]['parser']._optionals.title = category[c]['help']
		
		# Manage options
		category[c]['subparser'] = []
		for module in modules[c].keys():
			m = modules[c][module]
			category[c]['parser'].add_argument(m.options['command'], action=m.options['action'], dest=m.options['dest'], help=m.options['help'])
			
			# Manage all suboptions by modules
			if m.suboptions and m.name != 'thunderbird':
				tmp = []
				for sub in m.suboptions:
					tmp_subparser = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
					tmp_subparser._optionals.title = sub['title']
					if 'type' in sub:
						tmp_subparser.add_argument(sub['command'], type=sub['type'], action=sub['action'], dest=sub['dest'], help=sub['help'])
					else:
						tmp_subparser.add_argument(sub['command'], action=sub['action'], dest=sub['dest'], help=sub['help'])
					tmp.append(tmp_subparser)
					all_subparser.append(tmp_subparser)
				category[c]['subparser'] += tmp

	# ------------------------------------------- Print all -------------------------------------------
	parents = [PPoptional, PDump, Ppwd] + all_subparser + [PWrite]
	dic = {'all':{'parents':parents, 'help':'Run all modules', 'func': runModule}}
	for c in category:
		parser_tab = [PPoptional, PDump, Ppwd, category[c]['parser']]
		if 'subparser' in category[c]:
			if category[c]['subparser']:
				parser_tab += category[c]['subparser']
		parser_tab += [PWrite]
		dic_tmp = {c: {'parents': parser_tab, 'help':'Run %s module' % c, 'func': runModule}}
		dic = dict(dic.items() + dic_tmp.items())

	# 2- Main commands
	subparsers = parser.add_subparsers(help='Choose a main command')
	for d in dic:
		subparsers.add_parser(d, parents=dic[d]['parents'], help=dic[d]['help']).set_defaults(func=dic[d]['func'], auditType=d)

	# ------------------------------------------- Parse arguments -------------------------------------------
	
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)

	args 				= dict(parser.parse_args()._get_kwargs())
	arguments 			= parser.parse_args()
	category_choosed 	= args['auditType']

	quiet_mode()

	# Print the title
	constant.st.first_title()

	# Define constant variables
	output()
	verbosity()
	manage_advanced_options()
	
	if not constant.dump:
		print '[-] Please specify a dump directory or a mounted drive using "-local" or "-remote" options'
		sys.exit()
	
	start_time = time.time()

	for r in runLaZagne(category_choosed=category_choosed, password=constant.user_password, pwdhash=constant.user_pwdhash):
		pass

	write_in_file(stdoutRes)
	
	if not constant.quiet_mode:
		constant.st.print_footer()
		elapsed_time = time.time() - start_time
		print '\nelapsed time = ' + str(elapsed_time)
