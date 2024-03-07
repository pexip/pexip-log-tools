# Copyright 2023 Pexip AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#$invocation = (Get-Variable MyInvocation -Scope 0).Value
#$scriptPath = Split-Path $Invocation.MyCommand.Path
$downloadFolder = "C:\Tools\Scripts"
$backupFolder = "$downloadFolder\Backup"

# Hash table containing the script tiles to manage.
# Local file : Remote file
$FilesToManage = @{
    "$downloadFolder\Get-PexScripts.ps1" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/Get-PexScripts.ps1"
    "$downloadFolder\dbsummary.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/dbsummary.py"
    "$downloadFolder\logreader.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/logreader.py"
    "$downloadFolder\confhistory.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/confhistory.py"
    "$downloadFolder\connectivity.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/connectivity.py"
    "$downloadFolder\mjxsummary.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/mjxsummary.py"
    "$downloadFolder\teamsload.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/teamsload.py"
    "$downloadFolder\staticroutes.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/staticroutes.py"
    "$downloadFolder\Pexip_Log_Tools.ps1" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/Pexip_Log_Tools.ps1"
    "$downloadFolder\pexwebapps.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/pexwebapps.py"
    "$downloadFolder\vmotion.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/vmotion.py"
    "$downloadFolder\pexauthconfig.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/pexauthconfig.py"
    "$downloadFolder\pexidpconfig.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/pexidpconfig.py"
}

# Check to see if the backup folder exits
if (-Not (Test-Path -Path $backupFolder -PathType Container))
{
    New-Item $backupFolder -ItemType Directory
}

# Create a time stamp used to append to the backup file.
$timestamp = Get-Date -Format s | ForEach-Object { $_ -replace ":", "." }

# Setup Web client
#$wc = new-object System.Net.WebClient

# Check if new configuration file exists

        if (-not (Test-Path "c:\Tools\Scripts\Variables.ps1")) {
		Write-Warning "Due to a new configuration approach please provide answers the following values ( or just hit Enter for defaults )"
		$snapDir = Read-Host "Please enter the directory path for snaps (default: c:\Snaps)"
		if ([string]::IsNullOrEmpty($snapDir)) {
			$SnapDir = "C:\Snaps"
		}
		$askForTicketNumber = Read-Host "Do you want to be prompted for ticket number to be associated with a snapshot ? (y/n) (default: n)"
		if ($askForTicketNumber -eq "y") {
			$askForTicketNumber = $true
		} else {
			$askForTicketNumber = $false
		}
		$numberOfSnaps = Read-Host "Please enter the number of support log files to be processed by default by the logreader (default: 20)"
		if ([string]::IsNullOrEmpty($numberOfSnaps)) {
			$numberOfSnaps = 20
		}
		# Write values to config file
		Write-Host '$SnapDir ='`"$SnapDir`" *> c:\Tools\Scripts\Variables.ps1
		Write-Host '$askForTicketNumber ='`$$askForTicketNumber *>> c:\Tools\Scripts\Variables.ps1
		Write-Host '$numberOfSnaps ='`"$numberOfSnaps`" *>> c:\Tools\Scripts\Variables.ps1
		}		

# Loop through each item in the has table to see if
$FilesToManage.Keys | ForEach-Object {
    Write-Host ""
    Write-Host "Checking " $_

    if(-Not (Test-Path -Path $_ -PathType Leaf)) {
        New-Item -Path $_ -ItemType file
    }

    $LocalFile = Get-item -Path $_
    $TempFile = "$LocalFile.tmp"
    $RemoteFile = $FilesToManage.Item($_)

    # if the remote item hash differs from the local item hash,
    # then download the remote file and backup the local file.
    
    # Download the remote file to a temporary file. 
    Write-Host "Downloading `"$($RemoteFile)`""
    Invoke-WebRequest -Uri $RemoteFile -Outfile $TempFile
	
	# Check if the remote file length is 0
	$remoteFileLength = (Get-Item $TempFile).Length
    
	if ($remoteFileLength -eq 0) {
    Write-Host "The new version of the file is empty or could not be downloaded. Keeping the original file."
    Remove-Item $TempFile  # Delete the empty temporary file
	} else {
    # Compare the local file with the downloaded file
    if ((Get-FileHash $LocalFile).Hash -ne (Get-FileHash $TempFile).Hash)
    {
        Write-Host "New file differs from local file. Creating a backup and keeping the new file."
        $NewFileName = $LocalFile.BaseName + "_" + $timestamp + $LocalFile.Extension
        Move-Item -Path $LocalFile -Destination $backupFolder\$NewFileName
        Move-Item -Path $TempFile -Destination $LocalFile
		If ($_ -like "*Get-PexScripts.ps1") 
        {
            Write-Host "Looks like we have updated the Get-PexScripts.ps1 file, which is the file you are currently running."
            Write-Host "Re-running the script to get new changes."
            & "C:\Tools\Scripts\Get-PexScripts.ps1"
        }
    } else {
        Write-Host "Local file is the same as downloaded file. No update needed. Proceeding to clear."
        Remove-Item $TempFile  # Delete the temporary file since it's not needed
    }
}
}
