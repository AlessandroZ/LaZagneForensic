#!/usr/bin/env python
# -*- coding: utf-8 -*- 
import time
import os

date = time.strftime("%d%m%Y_%H%M%S")

class constant():
	folder_name 			= '.'
	file_name_results 		= 'credentials_{current_time}'.format(current_time=date) # the extention is added depending on the user output choice
	MAX_HELP_POSITION		= 27
	CURRENT_VERSION 		= '0.2'
	output 					= None
	file_logger 			= None
	
	# jitsi options
	jitsi_masterpass 		= None
	
	# total password found
	nbPasswordFound 		= 0
	passwordFound 			= []
	finalResults			= {}
	username 				= u''
	softwares_path = {
						'Dpapi'		:
											{
												'local'		: u'{root}/Users/{user}/AppData/', 
												'remote'	: u'{root}/Users/{user}/DPAPI',
											},
						'Dpapi_system'	:
											{
												'local'		: u'{root}/Windows/System32/Microsoft',
												'remote'	: u'{root}/System/DPAPI/', 
											},
						'Vault_system'	:
											{
												'local'		: u'{root}/Windows/System32/config/systemprofile/AppData/Local/Microsoft/Vault',
												'remote'	: u'{root}/System/DPAPI/Vault', 
											},

						##################### Mail ####################
						
						'Thunderbird'	:
											{
												'local'		: u'{root}/Users/{user}/AppData/Roaming/Thunderbird/Profiles',
												'remote'	: u'{root}/Users/{user}/Thunderbird',
											},

						##################### Browsers ####################
						
						'Firefox'		:
											{
												'local'		: u'{root}/Users/{user}/AppData/Roaming/Mozilla/Firefox/Profiles',
												'remote'	: u'{root}/Users/{user}/Firefox',
											},
						
						'Chrome'		:
											{
												'local'		: u'{root}/Users/{user}/AppData/Local/Google/Chrome/User Data', 
												'remote'	: u'{root}/Users/{user}/Chrome',
											},

						'Coccoc'		:
											{
												'local'		: u'{root}/Users/{user}/AppData/Local/CocCoc/Browser/User Data', 
												'remote'	: u'{root}/Users/{user}/Coccoc',
											},
						
						'Opera'		:
											{
												'local'		: u'{root}/Users/{user}/AppData/Roaming/Opera Software/Opera Stable', 
												'remote'	: u'{root}/Users/{user}/Opera',
											},

						##################### Chats ####################

						'Pidgin'		:
											{
												'local'		: u'{root}/Users/{user}/AppData/Roaming/.purple', 
												'remote'	: u'{root}/Users/{user}/Pidgin',
											},

						##################### Databases ####################

						'Dbvis'		:
											{
												'local'		: u'{root}/Users/{user}/.dbvis/config70', 
												'remote'	: u'{root}/Users/{user}/Dbvis',
											},

						'Robomongo'		:
											{
												'local'		: u'{root}/Users/{user}', 
												'remote'	: u'{root}/Users/{user}/Robomongo',
											},


						'Sqldeveloper'		:
											{
												'local'		: u'{root}/Users/{user}/AppData/Roaming/SQL Developer', 
												'remote'	: u'{root}/Users/{user}/SQL Developer',
											},

						'Squirrel'		:
											{
												'local'		: u'{root}/Users/{user}/.squirrel-sql', 
												'remote'	: u'{root}/Users/{user}/Squirrel',
											},

						##################### SVN ####################

						'Tortoise'		:
											{
												'local'		: u'{root}/Users/{user}/AppData/Roaming/Subversion/auth/svn.simple', 
												'remote'	: u'{root}/Users/{user}/Tortoise/svn.simple',
											},


						##################### Sysadmin ####################

						'Apachedirectorystudio'		:
											{
												'local'		: u'{root}/Users/{user}/.ApacheDirectoryStudio/.metadata/.plugins/org.apache.directory.studio.connection.core', 
												'remote'	: u'{root}/Users/{user}/ApacheDirectoryStudio',
											},

						'Filezilla'		:
											{
												'local'		: u'{root}/Users/{user}/AppData/Roaming/FileZilla', 
												'remote'	: u'{root}/Users/{user}/Filezilla',
											},
						'Ftpnavigator'		:
											{
												'local'		: u'{root}/FTP Navigator', 
												'remote'	: u'{root}/Users/{user}/FTP Navigator',
											},

						'Unattended'		:
											{
												'local'		: u'{root}/Windows', 
												'remote'	: u'{root}/System/Unattended',
											},

						##################### Windows ####################

						'Hives'		:
											{
												'local'		: u'{root}/Windows/System32/config', 
												'remote'	: u'{root}/System/Hives',
											},
						'Wifi'		:
											{
												'local'		: u'{root}/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces', 
												'remote'	: u'{root}/System/Wifi/Interfaces',
											},
					}

	hives 					= []
	quiet_mode 				= False

	# standart output
	st 						= None
	drive					= u'C'

	dump					= ''	# wait 'local' or 'remote' value
	root_dump 				= ''
	user_dpapi				= None
	user_password 			= None
	user_pwdhash 			= None
	module_to_exec_at_end	= []