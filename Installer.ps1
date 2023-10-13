# Define the default download folder and Send To folder
$defaultDownloadFolder = "c:\Tools\Scripts"
$SENDTO = [System.Environment]::GetFolderPath('SendTo')
$SYSDIR = [System.Environment]::GetFolderPath('System')
$downloadFolder = $null  # Initialize download folder

function DownloadScripts {
    # Ask the user for the destination folder
    $downloadFolder = Read-Host "Enter the destination folder for script downloads (default: $defaultDownloadFolder)"

    # Use the default folder if the user didn't provide one
    if ([string]::IsNullOrEmpty($downloadFolder)) {
        $downloadFolder = $defaultDownloadFolder
    }

    # Create the download folder if it doesn't exist
    if (-not (Test-Path -Path $downloadFolder)) {
        New-Item -Path $downloadFolder -ItemType Directory
    }

    # Define the files to download
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
    }

    # Download the files
    foreach ($file in $FilesToManage.GetEnumerator()) {
        $localPath = $file.Key
        $remoteURL = $file.Value

        Write-Host "Downloading $localPath"
        (New-Object System.Net.WebClient).DownloadFile($remoteURL, $localPath)
    }

    Write-Host "Download completed."
	Write-Host " "
	# Prompt the user to create a Send To shortcut
	CreateSendToShortcut

}

function CreateSendToShortcut {
    # Prompt the user to create a Send To shortcut
    $createSendToShortcut = Read-Host "Do you want to create a 'Send To' shortcut? (Yes/No, default: Yes)"

    if ($createSendToShortcut -eq "Yes" -or $createSendToShortcut -eq "") {
        $shortcutPath = Join-Path $SENDTO "Pexip Log Tools.lnk"
        $powershellPath = Join-Path $SYSDIR "WindowsPowerShell\v1.0\powershell.exe"
        $scriptPath = Join-Path $downloadFolder "Pexip_Log_Tools.ps1"

        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = $powershellPath
        $Shortcut.Arguments = "-file $scriptPath"
        $Shortcut.Save()

        Write-Host "Shortcut created: $shortcutPath"
    } else {
        Write-Host "No 'Send To' shortcut was created."
    }
}

# Display the welcome message
# Create a menu with options
do {
	Clear-Host
	Write-Host "Welcome to the Installer"
	Write-Host " "
    Write-Host "Please choose one of the following options:"
    Write-Host "1. Download Scripts"
    Write-Host "2. Create 'Send To' Shortcut"
    Write-Host "3. Exit"
    
    $choice = Read-Host "Select an option (1/2/3):"

    switch ($choice) {
        "1" { DownloadScripts }
        "2" { CreateSendToShortcut }
        "3" { break }
        default { Write-Host "Invalid option. Please select 1, 2, or 3." }
    }
} while ($choice -ne "3")
