# Define the default script download folder and Send To folder
$defaultScriptDownloadFolder = "c:\Tools\Scripts"
$SENDTO = [System.Environment]::GetFolderPath('SendTo')
$SYSDIR = [System.Environment]::GetFolderPath('System')
$ScriptDownloadFolder = $defaultScriptDownloadFolder  # Set the default script download folder

function DownloadScripts {
    # Display a warning and prompt the user to press Enter to continue
    Write-Warning "WARNING: Files will be downloaded to $defaultScriptDownloadFolder"
    Read-Host "Press Enter to continue..."

    # Create the download folder if it doesn't exist
    if (-not (Test-Path -Path $ScriptDownloadFolder)) {
        New-Item -Path $ScriptDownloadFolder -ItemType Directory
    }

    # Define the files to download
    $FilesToManage = @{
        "$ScriptDownloadFolder\Get-PexScripts.ps1" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/Get-PexScripts.ps1"
        "$ScriptDownloadFolder\dbsummary.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/dbsummary.py"
        "$ScriptDownloadFolder\logreader.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/logreader.py"
        "$ScriptDownloadFolder\confhistory.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/confhistory.py"
        "$ScriptDownloadFolder\connectivity.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/connectivity.py"
        "$ScriptDownloadFolder\mjxsummary.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/mjxsummary.py"
        "$ScriptDownloadFolder\teamsload.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/teamsload.py"
        "$ScriptDownloadFolder\staticroutes.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/staticroutes.py"
        "$ScriptDownloadFolder\Pexip_Log_Tools.ps1" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/Pexip_Log_Tools.ps1"
        "$ScriptDownloadFolder\pexwebapps.py" = "https://raw.githubusercontent.com/pexip/pexip-log-tools/master/pexwebapps.py"
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

    if ($createSendToShortcut -eq "No") {
        Write-Host "No 'Send To' shortcut was created."
    } else {
        # Treat no response as "Yes"
        if ([string]::IsNullOrEmpty($createSendToShortcut) -or $createSendToShortcut -eq "Yes") {
            $ScriptDownloadFolder = $defaultScriptDownloadFolder  # Set the default folder
        }
        $shortcutPath = Join-Path $SENDTO "Pexip Log Tools.lnk"
        $powershellPath = Join-Path $SYSDIR "WindowsPowerShell\v1.0\powershell.exe"
        $scriptPath = Join-Path $ScriptDownloadFolder "Pexip_Log_Tools.ps1"

        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = $powershellPath
        $Shortcut.Arguments = "-file $scriptPath"
        $Shortcut.Save()

        Write-Host "Shortcut created: $shortcutPath"
    }
}

# Display the welcome message and start the download
Write-Host ""
Write-Host "Welcome to the Pexip Log Tools Installer"
Write-Host ""
DownloadScripts
