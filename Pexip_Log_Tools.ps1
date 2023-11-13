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


# PS Module to process different log files, from a complete snapshot to a individual files
#Requires -Version 3.0
Write-Host "`nChecking for updates, please wait....`n"
& "C:\Tools\Scripts\Get-PexScripts.ps1"
# Read option variables
. c:\tools\scripts\Variables.ps1

########### Setup environment (should not need to be changed)

$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$appData = [Environment]::GetFolderPath('LocalApplicationData')
$programFiles86 = [Environment]::GetFolderPath('ProgramFilesX86')

# Check if Python 3.9.x is installed
if (Test-Path 'C:\Program Files\Python39\python.exe') {
    $PathToPython = 'C:\Program Files\Python39\python.exe'
}
# Check if Python 3.10.x is installed
elseif (Test-Path 'C:\Program Files\Python310\python.exe') {
    $PathToPython = 'C:\Program Files\Python310\python.exe'
}
# Python version not found
else {
    Write-Error 'Python 3.9.x or 3.10.x is not installed on this computer. Pexip Log Tools will not work.'
	Write-Host "Please press Enter to close the window."
	Read-Host
	exit 1  # Exit with an error code to indicate a problem
}

$PathToGrep = "Gow\bin\grep.exe"
$PathToNotepad = "Notepad++\notepad++.exe"
$PathToGrepWin = "grepWin\grepWin.exe"
$PathToFile = "C:\Tools\file-5.03-bin\bin\file.exe"
$DBSummaryScript = "C:\Tools\Scripts\dbsummary.py"
$LogreaderScript = "C:\Tools\Scripts\logreader.py"
$vMotionScript = "C:\Tools\Scripts\detect_vMotion.py"
$ConfHistoryScript = "C:\Tools\Scripts\confhistory.py"
$ConnectivityScript = "C:\Tools\Scripts\connectivity.py"
$MJXScript = "C:\Tools\Scripts\mjxsummary.py"
$OutputFolder = "C:\Tools\Scripts\Output\"

$LogReaderError = "LogReaderError.txt"
$DBSummaryError ="DBSummaryError.txt"
$ConfHistoryError = "ConfHistoryError.txt"
$ConnectivityError = "ConnectivityError.txt"
$MJXError = "MJXError.txt"

$SupportLog = "support.log"
$DeveloperLog = "developer.log"
$OSStatusLog = "osstatus.log"
$LogReaderOutput = "Pex_Report_Logreader"
$LogDir = "var\log"
$ParsedLogDir = "parsed"
$DBReport = "Pex_Report_DBSummary.txt"
$vMotionReport = "Pex_Health_vMotion.txt"
$ConfHistoryReport = "Pex_Report_ConfHistory.txt"
$ConnectivityReport = "Pex_Report_Connectivity.txt"
$MJXReport = "Pex_Report_MJXSummary.txt"
$IrregularPulseText = "Pex_Health_Irregular_Pulse.txt"
$IrregularPingText = "Pex_Health_Irregular_Ping.txt"
$RectorStallingText = "Pex_Health_Reactor_Stalling.txt"

$env:PYTHONIOENCODING="UTF-8"
$SnapArray = @()
$FolderArray = @()
$LogArray = @()
$AnythingElseArray = @()

$EnvironmentHash = @{
    "grepWin 1.6.16" = $PathToGrepWin;
    "Notepad++" = $PathToNotepad;
	"grep" = $PathToGrep;
}

Set-StrictMode -Version latest

function Test-PexEnvironment {
    $global:PathToNotepad = $null
    $global:PathToGrepWin = $null
    $global:PathToGrep = $null

    foreach ($appName in $EnvironmentHash.Keys) {
        $path = $EnvironmentHash[$appName]
        $fullPath = Join-Path $programFiles $path

        if (-not (Test-Path $fullPath)) {
            $fullPath = Join-Path $programFiles86 $path

            if (-not (Test-Path $fullPath)) {
                $fullPath = Join-Path $appData\Apps $path

                if (-not (Test-Path $fullPath)) {
                    Write-Error "File not found: $path in $programFiles86 or $appData or $programFiles. Please reinstall the missing file in either of these locations and try again. "
					Write-Host "Please press Enter to close the window."
					Read-Host
					exit 1  # Exit with an error code to indicate a problem
                } else {
                    # Update global variables with the full path
                    if ($appName -eq "Notepad++") {
                        $global:PathToNotepad = $fullPath
                    } elseif ($appName -eq "grepWin 1.6.16") {
                        $global:PathToGrepWin = $fullPath
                    } elseif ($appName -eq "grep") {
                        $global:PathToGrep = $fullPath
                    }
                }
            } else {
                # Update global variables with the full path
                if ($appName -eq "Notepad++") {
                    $global:PathToNotepad = $fullPath
                } elseif ($appName -eq "grepWin 1.6.16") {
                    $global:PathToGrepWin = $fullPath
                } elseif ($appName -eq "grep") {
                    $global:PathToGrep = $fullPath
                }
            }
        } else {
            # Update global variables with the full path
            if ($appName -eq "Notepad++") {
                $global:PathToNotepad = $fullPath
            } elseif ($appName -eq "grepWin 1.6.16") {
                $global:PathToGrepWin = $fullPath
            } elseif ($appName -eq "grep") {
                $global:PathToGrep = $fullPath
            }
        }
    }

    return $true
}

function Test-PexLogs {
    <#
    .SYNOPSIS
    Takes diagnostic snapfolder(s), and test the log files for basic health information.
    .DESCRIPTION
    Input is a reference to snapfolder(s). This parameter takes pipelined input.

    The function will check the log files for basic health information such as Irregular Pulse, Ping and Reactor Staling events. The check files are saved into the parsed subfolder.
    .EXAMPLE
    Test-PexLogs -Snapshots C:\Snaps\diagnostic_snapshot_mgtnode_17_01_01_15_00_00
    .PARAMETER Snapfolders
    The list of of snapshot folders to test.
    #>
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage='A list of Pexip snap folders you want to test.')]
        [Alias('Snaps')]
        $Snapfolders
    )

    begin {
        $FailedConvert = $false
        Write-Debug "Test-PexLogs - Begin block (pre-pipeline) on $Snapfolders"
        if (-not(Test-PexEnvironment)) {return $false}
        $vMotionError = "vMotionSError.txt"
        $TempError = "TempError-VM"
    }

    process {
        Write-Host "`nProcessing the snap for health information (Irregular Pulse, Ping and Reactor Staling events), please wait....`n"
        Write-Verbose "Test-PexLogs - Process block (pre-pipeline) on $Snapfolders"

        Write-Debug "Test-PexLogs - Process block, enumerate $Snapfolders"
        # Enumerate the snap folder passed in
        foreach ($Snap in $Snapfolders) {
            if ($pscmdlet.ShouldProcess($Snap) -and ($Snap -ne $false)) {

                if (Test-Path -Path $Snap -PathType Container ){
                    # Check to see if the snap folder matches the diagnostic snap pattern
                    if ($Snap | Select-String -Pattern "diagnostic_snapshot.*?(\\|$)") {
                        & $PathToGrep -Eih "Irregular Pulse" "$Snap\$LogDir\*$SupportLog*" | Sort-Object | Set-Content "$Snap\$LogDir\$ParsedLogDir\$IrregularPulseText"
                        & $PathToGrep -Eih "Irregular Ping" "$Snap\$LogDir\*$DeveloperLog*" | Sort-Object | Set-Content "$Snap\$LogDir\$ParsedLogDir\$IrregularPingText"
                        & $PathToGrep -Eih "Reactor Stalling" "$Snap\$LogDir\*$DeveloperLog*" | Sort-Object | Set-Content "$Snap\$LogDir\$ParsedLogDir\$RectorStallingText"
                        #Start-Process $PathToGrep -ArgumentList ('-Eih "Irregular Ping"', "$Snap\$LogDir\$DeveloperLog*") -RedirectStandardOutput "$Snap\$LogDir\$ParsedLogDir\$IrregularPingText" -NoNewWindow
                        #Start-Process $PathToGrep -ArgumentList ('-Eih "Reactor Stalling"', "$Snap\$LogDir\$DeveloperLog*") -RedirectStandardOutput "$Snap\$LogDir\$ParsedLogDir\$RectorStallingText" -NoNewWindow

                        Start-Process $PathToPython -ArgumentList ("$vMotionScript", "`"$Snap`"") -RedirectStandardOutput "$Snap\$LogDir\$ParsedLogDir\$vMotionReport" -RedirectStandardError "$OutputFolder$TempError" -NoNewWindow -Wait

                        Write-Debug -Message "Test-PexLogs - Process block, enumerate $True"
                        Return "$Snap\$LogDir\$ParsedLogDir\$IrregularPulseText", "$Snap\$LogDir\$ParsedLogDir\$IrregularPingText", "$Snap\$LogDir\$ParsedLogDir\$RectorStallingText", "$Snap\$LogDir\$ParsedLogDir\$vMotionReport"
                    }
                }
            }
            Write-Debug -Message "Test-PexLogs - Process block, enumerate $false"
            Return $false
        }
    }
}


function New-PexLogReader {
    <#
    .SYNOPSIS
    Takes an array of log file names, and return a file name to the new LogReader Report.
    .DESCRIPTION
    Input is an array of file names. The snapshot folder will be expected to be in the format "diagnostic_snapshot_<name>.<date>",
    so this command will not provide a result if this is not the case. This parameter takes pipelined input.

    When you reference a path name to a snapshot folder, the result will be a text string to the DBSummary report for that snapshot.

    The returned result is a array of: "LogReader File", "LogReader Process ID", "Temp Error log file name"
    If there is a failure, the function returns $false
    .EXAMPLE
    New-PexLogReader -path C:\Snaps\diagnostic_snapshot_mgtnode_17_01_01_15_00_00 -SupportLogFiles support.log, support.log.1
    .EXAMPLE
    Get-ChildItem C:\Snaps\diagnostic_snapshot_mgtnode_17_01_01* -Directory | New-PexLogReader
    .PARAMETER SupportLogFiles
    An array of log file names to parse.
    .PARAMETER SupportLogFolder
    The snapshot folder where the logs are located.
    #>
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage='Give list of log file to run through LogReader.')]
        [Alias('Logs')]
        [String[]]$SupportLogFiles,

        [Parameter(Mandatory=$True,
        HelpMessage='Give the path to the folder that contains the logs you wish to process.')]
        [Alias('Path')]
        [String]$SupportLogFolder
    )
    begin {
        $SupportLogArray = @()
        $OtherLogArray = @()
        $LogReaderFail = $false
        Write-Debug "New-PexLogReader - begin block (pre-pipeline) on $SupportLogFiles"
        if (-not(Test-PexEnvironment)) {return $false}
        $TempError = "TempError-Log"
    }

    process {
        Write-Host "`nProcessing the support logs to create a call Summary (LogReader), please wait....`n"
        Write-Verbose "New-PexLogReader - Process block, enumeration on $SupportLogFiles"
        $CurrentLogFolder = Split-Path -Path $SupportLogFiles[0] -Parent

        # Setup an new folder to store Parsed log files
        if (-Not (Test-Path $CurrentLogFolder\$ParsedLogDir)) {
            New-Item -Path "$CurrentLogFolder\$ParsedLogDir" -ItemType Directory | out-null
        }

        # Enumerate the snap folder passed in
        foreach ($Log in $SupportLogFiles) {
            if ($pscmdlet.ShouldProcess($Log) -and ($Log -ne $false)) {

                $CurrentLogFolder = Split-Path -Path $Log -Parent

                # Setup an new folder to store Parsed log files
                if ($CurrentLogFolder -ne $SupportLogFolder) {
                    Write-Warning "New-PexLogReader - Log file must be in the same folder, stopped at $Log"
                    $LogReaderFail = $True
                    Write-Debug -Message "New-PexLogReader - Return $false"
                    return $false
                }

                $SupportLogArray += Split-Path $Log -Leaf
            }
        }
    }


    end {
        Write-Verbose "New-PexLogReader - End block"

        if ($LogReaderFail -eq $true) {
            Write-Debug "New-PexLogReader - Return $false"
            return $false
        }
        # Find the number of item (log files) that were passed into the script. Could have use $args as well, but $SupportLogArray2 with only one item in it is not an array (of ITEMs), so length is huge
        $SupportLogArrayCount = $SupportLogFiles.Length

        if (($SupportLogArrayCount -gt 0) -and ($SupportLogFiles -ne $false)) {
            # Turn the textual array of log file name into a Get-ChildItem object as we can use the ITEM object in file manipulation.
            $SupportLogArray2 = Get-ChildItem -path "$SupportLogFolder\*" -Include $SupportLogArray | Sort-Object LastWriteTime -Descending


            # Create an extension sequence to append to the logreader output.
            if ($SupportLogArrayCount -gt 1) {
                $SupportLogExtensions = $SupportLogArray2[0].Extension + "-" + ($SupportLogArray2[$SupportLogArrayCount-1].Extension).Substring(1) + ".txt"
            }
            Else {
                if ($SupportLogArray2.Extension -ne ".txt") {
                    $SupportLogExtensions = $SupportLogArray2.Extension + ".txt"
                }
                else {
                    $SupportLogExtensions = "." + ($SupportLogArray2.CreationTime | Get-Date -f "yyyy-MM-dd_hh-mm") + ".txt"
                }
            }
            Push-Location
            Set-Location -Path $SupportLogFolder

            # Run LogReader report on current Log files and pipe the result out to a text file
            $LogReaderProcess = Start-Process $PathToPython -ArgumentList "$LogreaderScript $($SupportLogArray2.Name)" -RedirectStandardOutput "$ParsedLogDir\$LogReaderOutput$SupportLogExtensions" -RedirectStandardError "$OutputFolder$TempError" -NoNewWindow -PassThru

            Pop-Location
            Write-Debug -Message "New-PexLogReader - Return $SupportLogFolder\$ParsedLogDir\$LogReaderOutput$SupportLogExtensions, Process ID $LogReaderProcess.id"
            return "$SupportLogFolder\$ParsedLogDir\$LogReaderOutput$SupportLogExtensions", $LogReaderProcess, $TempError
        }
        else {
            Write-Warning "New-PexLogReader - Unable to process any support logs to create Call Summary."
            Write-Debug -Message "New-PexLogReader - Return $false"
            return $false
        }
    }
}

function New-PexSummary {
    <#
    .SYNOPSIS
    Takes path name to an expanded snap folder, and return a file name to the new Summary Report (DB Summary, Conf History or Connectivity)
    .DESCRIPTION
    Input is a reference to an expanded snapshot folder stored in 'C:\Snaps'. The snapshot folder will be expected to be in the format "diagnostic_snapshot_<name>.<date>",
    so this command will not provide a result if this is not the case. This parameter takes pipelined input.

    When you reference a path name to a snapshot folder, the result will be a text string to the Summary report for that snapshot.
    .EXAMPLE
    New-PexSummary -path C:\Snaps\diagnostic_snapshot_mgtnode_17_01_01_15_00_00 -Script "C:\Tools\Scripts\dbsummary.py" -Report "DBSummary.txt" -Error "DBSummaryError.txt"
    .EXAMPLE
    Get-ChildItem C:\Snaps\diagnostic_snapshot_mgtnode_17_01_01* -Directory | New-PexSummary
    .PARAMETER Snapfolders
    The list of snapshot folders to query.
    .PARAMETER ScriptFile
    The script file to run against the snap.
    .PARAMETER ReportFile
    The report file to write to.
    .PARAMETER SummaryError
    The error file to write to.
    #>
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage='Give the path to the folder that contains the expanded snapshot.')]
        [Alias('Path')]
        [String[]]$Snapfolders,

        [Parameter(Mandatory=$True,
        HelpMessage='Give the path script file you want to run.')]
        [Alias('Script')]
        [String]$ScriptFile,

        [Parameter(Mandatory=$True,
        HelpMessage='Give the file name of the report you want to save.')]
        [Alias('Report')]
        [String]$ReportFile,

        [Parameter(Mandatory=$True,
        HelpMessage='Give the file name of the error file you want to save.')]
        [Alias('Error')]
        [String]$SummaryError
    )
    begin {
        Write-Debug "New-PexSummary - begin block (pre-pipeline) on $Snapfolders"
        if (-not(Test-PexEnvironment)) {return $false}
        $TempError = "TempError-summary"
    }

    process {
        Write-Verbose "New-PexSummary - Process block, enumeration on $Snapfolders"
        # Enumerate the snap folder passed in
        foreach ($Snap in $Snapfolders) {
            if ($pscmdlet.ShouldProcess($Snap) -and (-not($Snap -eq $false))) {

                #double check to see if this is a proper folder and matches the snapshot older pattern and in not a sub folder .
                if ((Test-Path -Path $Snap -PathType Container) -and (($Snap | Select-String -Pattern "diagnostic_snapshot.*?(\\|$)") -and (-not($Snap | Select-String -Pattern "diagnostic_snapshot.*?(\\|$).")))) {
                    Push-Location
                    Set-Location $Snap
                    Write-Debug "New-PexSummary - Inside $Snap"

                    # Run report on current config and pipe the result out to a text file
                    Start-Process $PathToPython -ArgumentList ("$ScriptFile", "`"$Snap`"") -RedirectStandardOutput "$Snap\$LogDir\$ParsedLogDir\$ReportFile" -RedirectStandardError "$OutputFolder$TempError" -NoNewWindow -Wait
                    if ($null -eq (Get-Content -Path "$Snap\$LogDir\$ParsedLogDir\$ReportFile")) {
                        Write-Output "Nothing to show. Perhaps check the error log file in the same folder." | Add-Content -Path "$Snap\$LogDir\$ParsedLogDir\$ReportFile"
                    }


                    Pop-Location
                    Write-Debug "New-PexSummary - Return $Snap\$LogDir\$ParsedLogDir\$ReportFile"
                    return "$Snap\$LogDir\$ParsedLogDir\$ReportFile"
                }
            }
        }
        Write-Debug "New-PexSummary - Return $false"
        return $false
    }
}

function Convert-PexLogs {
    <#
    .SYNOPSIS
    Takes individual log file(s), parses them (removing the ^M), and moves them to the parsed folder.
    .DESCRIPTION
    Input is a reference to log file(s) within a snapshot that you want to process, such as the Support, Developer or OSstatus logs.
    This parameter takes pipelined input.

    The process will remove the line concatenations (^M) of log line, and replace these with new line and a carriage return feed in order to make them more readable,
    then move these into the Parsed subfolder.

    Returns 3 items as an array: CurrentLogFolder, CurrentSnapFolder, GrepWinProc.
    If the conversion fails, these elements will be $false.
    .EXAMPLE
    Convert-PexSnap -Logs unified_support.log.100, unified_support.log.101
    .EXAMPLE
    Get-Item C:\Snaps\diagnostic_snapshot_mgtnode_17_01_01_15_00_00 | Convert-PexSnap
    .PARAMETER LogFiles
    The list of files names to query. Must be within the same folder.
    #>
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage='A list of Pexip logs you want to process.')]
        [Alias('Logs')]
        $LogFiles
    )

    begin {
        $FailedConvert = $false
        Write-Debug "Convert-PexLog - Begin block (pre-pipeline) on $LogFiles"
        if (-not(Test-PexEnvironment)) {return $false}
    }

    process {
        Write-Host "`nProcessing the logs to unconcatenate files (grepWin), please wait....`n"
        Write-Verbose "Convert-PexLog - Process block (pre-pipeline) on $LogFiles"
        if ($LogFiles.GetType().IsArray) {
            $CurrentLogFolder = Split-Path -Path $LogFiles[0] -Parent
        }
        else {
            $CurrentLogFolder = Split-Path -Path $LogFiles
        }

        $CurrentSnapFolder = (Split-Path -Path (Split-Path -Path $CurrentLogFolder -Parent) -Parent)
        if (-not($CurrentSnapFolder | Select-String -Pattern "diagnostic_snapshot.*?(\\|$)")) {
            $CurrentSnapFolder = $false
        }

        # Setup an new folder to store Parsed log files
        if (-Not (Test-Path $CurrentLogFolder\$ParsedLogDir)) {
            New-Item -Path "$CurrentLogFolder\$ParsedLogDir" -ItemType Directory | out-null
            Write-Debug "Convert-PexLogs - Process block created the $CurrentLogFolder\$ParsedLogDir folder."
        }

        Write-Debug "Convert-PexLog - Process block, enumerate $LogFiles"
        # Enumerate the snap folder passed in
        foreach ($Log in $LogFiles) {
            if ($pscmdlet.ShouldProcess($Log) -and ($Log -ne $false)) {

                # Double check to see if the item is a file.
                if (Test-Path -Path $Log -PathType Leaf) {
                    Write-Debug "Convert-PexLog - Inside $Log"

                    # Check to see if the parent folder of the item is the same for all items.
                    if ((Split-Path -Path $Log -Parent) -ne ($CurrentLogFolder)) {
                        Write-Warning -Message "Convert-PexLog - Can't process logs files in different snap folders."
                        $FailedConvert = $True
                        return $false, $false, $false
                    }

                    # Get log file name
                    $BaseName = Split-Path -Path $Log -Leaf

                    # Check to see if the Parsed file exist, if not, copy the original to the Parsed subfolder.
                    $ParsedLogFile = Join-Path -Path $CurrentLogFolder -ChildPath "$ParsedLogDir\$BaseName"
                    if (-Not (Test-Path -Path $ParsedLogFile)) {
                        Copy-Item -Path $Log -Destination $ParsedLogFile
                    }
                }
            }
        }
    }

    end {
        Write-Verbose "Convert-PexLog - End $Log"

        # If the conversion of the files has failed, return nothing.
        If ($FailedConvert -eq $True) {
            Write-Warning -Message "Convert-PexLog - Returns $false"
            return $false, $false, $false
        }
        else {
            # Setup parsing for log files
            $GrepWinArgumentList = """/searchpath:""$CurrentLogFolder\$ParsedLogDir"" /k:no /u:no /size:-1 /searchfor:""\^M"" /regex:yes /replacewith:""\r\n"" /filemaskregex:"".*dev.*|.*oss.*|.*support.*"" /executeReplace /closedialog"

            # Parse those files via grepwin in order to expand the log files.
            Write-Verbose "Convert-PexLog - Running Support Logs through GrepWin to Expand."
            $GrepWinProc = Start-Process $PathToGrepWin -ArgumentList "$GrepWinArgumentList" -PassThru

            # Waits for the GrepWin process to finish before continuing
            # Wait-Process $GrepWinProc.Id -ErrorAction SilentlyContinue

            # Delete unused backups
            # Remove-Item -Path (Join-Path "$CurrentLogFolder\$ParsedLogDir" "*.bak" )

            Write-Debug -Message "Convert-PexLog - Return $CurrentLogFolder"
            return $CurrentLogFolder,$CurrentSnapFolder, $GrepWinProc
        }
    }
}


function Split-PexLogs {
    <#
    .SYNOPSIS
    Takes list of Log files to process, and separates out the support logs, which can then be used for LogReader.
    .DESCRIPTION
    Input is a set of Pexip log files from a single folder, such as the Support, Developer and OSStatus Logs. These logs in particular use line concatenation with the ^M delimiter,
    This parameter takes pipelined input.

    When you reference a path name to a snapshot folder, the function will return the first 20 support files.
    .EXAMPLE
    Split-PexLogs -LogFiles C:\Snaps\diagnostic_snapshot_mgtnode_17_01_01_15_00_00
    .PARAMETER LogFiles
    The list of log files to split query.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage='Give the list of Log files you wish to split.')]
        [Alias('Path')]
        [String[]]$LogFiles
    )
    begin {
        $SupportLogArray = @()
        $OtherLogArray = @()
    }
    process {
        Write-Verbose "Split-PexLogs - Process block, enumerate $LogFiles"
        if ($LogFiles.GetType().IsArray) {
            $CurrentLogFolder = Split-Path -Path $LogFiles[0] -Parent
        }
        else {
            $CurrentLogFolder = Split-Path -Path $LogFiles
        }

        # Enumerate the snap folder passed in
        foreach ($Log in $LogFiles) {
            if ($Log -ne $false) {

                # Double check to see if the item is a file.
                if (Test-Path -Path $Log -PathType Leaf) {
                    Write-Debug "Split-PexLogs - Inside $Log"

                    # Check to see if the parent folder of the item is the same for all items.
                    if ((Split-Path -Path $Log -Parent) -ne ($CurrentLogFolder)) {
                        Write-Warning -Message "Split-PexLogs - Can't process logs files in different snap folders."
                        Write-Debug -Message "Split-PexLogs - Returns $false"
                        return $false, $false
                    }

                    # Gather the support log files together and separate out other files
                    if (Select-String -Path $Log -Pattern "\^M" -quiet) {
                        # Gather the support log files together and separate out other files
                        if ($Log | Select-String -Pattern "support\.[log|txt]") {
                            $SupportLogArray += $Log
                        }
                        else {
                            $OtherLogArray += $Log
                        }
                    }
                }
            }
        }
    }

    end {
        Write-Verbose "Split-PexLogs - End block, enumeration on $LogFiles"
        if (($SupportLogArray.Length -eq 0) -and ($OtherLogArray.Length -eq 0)) {
            Write-Warning -Message "Convert-PexLog - No unconcatenated log files could be found. Logreader requires these files in order to create a call report."
            Write-Debug -Message "Convert-PexLog - Return $false"
            return $false, $false
        }
        elseif ($SupportLogArray.Length -eq 0) {
            Write-Warning -Message "Convert-PexLog - No unconcatenated support log files could be found. LogReader requires these files in order to create a call report."
            Write-Debug -Message "Convert-PexLog - Return $false"
            return $false, $false
        }
        else {
            Write-Debug "Split-PexLogs - Return $SupportLogArray, $OtherLogArray"
            Return $SupportLogArray, $OtherLogArray
        }
    }
}

function Get-PexLogs {
    <#
    .SYNOPSIS
    Takes path name to an expanded snap folder, and return a list of Log files to process.
    .DESCRIPTION
    Input is a reference to an expanded snapshot folder stored in 'C:\Snaps'. The snapshot folder will be expected to be in the format "diagnostic_snapshot_<name>.<date>",
    so this command will not provide a result if this is not the case. This parameter takes pipelined input.

    When you reference a path name to a snapshot folder, the function will return the first 20 support files.

    Returns an array of support log files.
    If there are no files, the returned result will be $false
    .EXAMPLE
    Get-PexSnap -path C:\Snaps\diagnostic_snapshot_mgtnode_17_01_01_15_00_00
    .EXAMPLE
    Get-ChildItem C:\Snaps\diagnostic_snapshot_mgtnode_17_01_01* -Directory | Get-PexSnap
    .PARAMETER Snapfolders
    The list of snapshot folders to query.
    .PARAMETER NumberOfSnaps
    The number of support log files to return from the snapshot. The default is 20.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage='Give the path to the folder that contains the expanded snapshot.')]
        [Alias('Path')]
        [String[]]$Snapfolders
    )

    process {
        Write-Verbose "Get-PexLogs - Process block, enumeration on $Snapfolders"
        # Enumerate the snap folder passed in
        foreach ($Snap in $Snapfolders) {
            if ($Snap -ne $false) {

                #double check to see if this is a proper folder and matches the snapshot older pattern and in not a sub folder .
                if ((Test-Path -Path $Snap -PathType Container) -and (($Snap | Select-String -Pattern "diagnostic_snapshot.*?(\\|$)") -and (-not($Snap | Select-String -Pattern "diagnostic_snapshot.*?(\\|$).")))) {
                    Write-Debug "Get-PexLogs - Inside $Snap"

                    # Create an array to hold the names of the first 20 Support Log files
                    $LogArray = Get-ChildItem -path "$Snap\$LogDir" -Filter *$SupportLog* | Sort-Object LastWriteTime -Descending | Select-Object -ExpandProperty FullName -first $NumberOfSnaps

                    # Check to see if the returned array is $null (i.e. there are no support log files)
                    if ($null -eq $LogArray) {
                        Write-Debug "Get-PexLogs - Returns $false"
                        return $false
                    }
                    else {
                        Write-Debug "Get-PexLogs - Returns $LogArray"
                        return $LogArray
                    }
                }
                else {
                    Write-Warning -message "Get-PexLogs - Unable to gather log files from $Snap."
                    Write-Debug "Get-PexLogs - Returns $false"
                    return $false
                }
            }
        }
    }
}


function Expand-PexSnap {
    <#
    .SYNOPSIS
    Takes a set of Pexip Diagnostic Snapshots (diagnostic_snapshot_<name>.<date>.tgz files) and expands them into the 'C:\Snaps' folder.
    .DESCRIPTION
    Input is a reference to a list of snapshot files, which will then be expanded and moved to the hardcoded Snaps folder at 'C:\Snaps'.
    The snapshot files are expected to match the file name "diagnostic_snapshot_<name>.<date>.tgz", so will not provide a result if this is not the case.
    This parameter takes pipelined input.
    .EXAMPLE
    Expand-PexSnap -Snapshots diagnostic_snapshot_mgtnode_17_01_01_15_00_00.tgz
    .EXAMPLE
    Get-ChildItem *.tgz | Expand-PexSnap
    .PARAMETER Snapshots
    The list of snapshot names to query.
    #>
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage='A list Pexip diagnostic snapshot(s) you want to process.')]
        [Alias('snaps')]
        [String[]]$Snapshots
    )

    begin {
        Write-Debug "Expand-PexSnap - Begin block (pre-pipeline) on $Snapshots"
        if (-not(Test-PexEnvironment)) {return $false}
        $7ZipErrorOuter = "7ZipError.txt"
        $7ZipErrorInner = "7ZipError.txt"
        $TempError ="TempError-7"
    }

    process {
        Write-Host "`nExpanding the diagnostic snapshot file, please wait....`n"
        Write-Debug "Expand-PexSnap - Process block, enumerate $Snapshots"
        foreach ($Snap in $Snapshots) {
            if ($pscmdlet.ShouldProcess($Snap)) {

                # Double check the name of the item we are processing is both a file and matches the normal snap naming convention.
                if (($Snap | Select-String -Pattern ".*diagnostic_snapshot.*\.tgz") -and (Test-Path -Path $Snap -PathType Leaf)) {
                    Write-Debug "Expand-PexSnap - File matches pattern, processing and expanding."
                    # Get Snap file name without extension
                    $BaseName = Get-Item $Snap | Select-Object -ExpandProperty BaseName
                    Write-Debug "Expand-PexSnap - The snap filename without the extension is `'$BaseName`'."

                    #Create destination folder and Unzip log files
					New-Item -ItemType Directory -Force -Path "$SnapDir\$BaseName"
                    tar -xzf "$Snapshots" --directory "$SnapDir\$BaseName"

                    Get-ChildItem -path "$($SnapDir)\$BaseName" | Where-Object {$_.Name -match "^(.*tmp|$BaseName|tmp.*).*(\.)?(tgz|tar)$"} | Remove-Item
                    Write-Verbose "Expand-PexSnap - Removed the inner TGZ file from the expanded folder to save space."

                    # Move original snap to working directory (overwrite)
                    Move-Item -Force $Snap $($SnapDir)
                    Write-Verbose "Expand-PexSnap - Moved the original snap the 'C:\Snaps' folder."

                    # Setup an new folder to store Parsed log files
                    if (-Not (Test-Path "$($SnapDir)\$BaseName\$LogDir\$ParsedLogDir")) {
                        New-Item -Path "$($SnapDir)\$BaseName\$LogDir\$ParsedLogDir" -ItemType Directory | out-null
                        Write-Debug "Expand-PexSnap - Created the `"$($SnapDir)\$BaseName\$LogDir\$ParsedLogDir`" folder."
                    }
                    Write-Debug "Expand-PexSnap - Returns `"$($SnapDir)\$BaseName`"."
                    return "$($SnapDir)\$BaseName"
                }
                else {
                    Write-Warning -message "Expand-PexSnap - Unable to recognise the file $Snap as a valid Pexip snapshot. `nThe file name downloaded will be in the format 'diagnostic_snapshot_<Name>_<date>.tgz'."
                    Write-Debug "Expand-PexSnap - Returns $false"
                    return $false
                }
            }
        }
    }
}

# Function to decrypt file
function Unprotect-PexFile {
    [CmdletBinding(SupportsShouldProcess=$True,ConfirmImpact='Low')]
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        HelpMessage='A file you want to decrypt.')]
        [Alias("Snap","Item", "File")]
        [String]$FileNameToProcess
    )

    process {
        $FileItem = Get-Item $FileNameToProcess

        if ($pscmdlet.ShouldProcess($FileItem))
        {

            if (-Not (Test-Path -Path $PathToFile -PathType Leaf)) {
                Write-Warning -Message "Cannot detect if the file is encrypted as 'File' is missing in $PathToFile"
                Write-Warning -Message "The may cause issues if attempting to unzip an encrypted file."
                Write-Warning -Message "Will continue and assume that the file is OK."
                #Pause
                #Exit 1
            }
            else {
                # Use the GNU tool 'file.exe' to determine if the file is readable as a non 'data' file.
                # If not, it's probably encrypted.
                if (& $PathToFile $FileItem | Select-String -pattern "; data" -quiet)
                {
                    Move-Item -Path $FileItem -Destination "$($FileItem.FullName).bak"
                    Write-Host "Please Enter the key to decrypt the file :" $FileItem.Name
                    Write-Host
                    $Result = ($host.ui.ReadLine()).TrimEnd()

                    & openssl aes-256-cbc -d -salt -pbkdf2 -out "$($FileItem.FullName)" -pass "pass`:$Result" -md "sha256" -in "$($FileItem.FullName).bak"

                    # Use the GNU tool 'file.exe' to determine if the file is readable as a non 'data' file.
                    # If not, then decryption probably failed so restore the file.
                    # PCAPNG files (Wireshark), will still read as data files, so ignore checking those.
                    if (((& $PathToFile $FileItem | Select-String -pattern "; data" -quiet) -eq $true) -and ($FileItem.Extension -ne ".pcap"))
                    {
                        Write-Warning "The file did not decrypt properly, the key may be wrong."
                        Write-Warning "Restoring original file and exiting."
                        Remove-Item $FileItem
                        Move-Item -Path "$($FileItem.FullName).bak" -Destination $FileItem
                        pause
                        Exit 0
                    }
                    else
                    {
                        Write-Host "Decryption Complete."
                        Remove-Item "$($FileItem.FullName).bak"
                    }
                }
            }
        }
    }
}

# Script starts here

# Test to see if arguments (expecting file/folder names) have been passed into the script.
if ($args.Count -eq 0) {
    Write-Warning "This script requires at least one (or more) files/folders to be passed in, such as Diagnostic Snapshot compressed files, Log files, or the Diagnostic Snapshot expanded folder"
    pause
    exit 0
}
# Test to see if the Environment is setup correctly.
else {

    # Enumerate all passed in arguments
    foreach ($item in $args) {
        Write-Verbose "The item about to be processed is: $item"

        # Check to see if the current item is a valid file
        if (Test-Path -path $item -PathType Leaf) {
            # Extract the file name if it looks like a diagnostic snapshot
            if ($item -match "diagnostic_snapshot.*\.tgz") {
                $SnapArray += $item #| Select-String -Pattern "diagnostic_snapshot.*\.tgz"
            }
            # Extract the file name if it looks like a log file
            elseif ($item -match "[support|developer|osstatus]\.[log|txt]") {
                $LogArray += $item #| Select-String -Pattern "[support|developer|osstatus]\.[log|txt]"
            }
            # Extract the file name it is anything else
            else {
                $AnythingElseArray += $item
            }
        }
        # Check to see if the current item is a valid folder
        elseif (Test-Path -path $item -PathType Container) {
            # Check to see if the folder name matches the snapshot folder name pattern, and is not a sub folder of the snap.
            if (($item | Select-String -Pattern "diagnostic_snapshot.*?(\\|$)") -and (-not($item | Select-String -Pattern "diagnostic_snapshot.*?(\\|$)."))) {
                $FolderArray += $item
            }
        }
    }

    if ($SnapArray.count -gt 0) {

        Write-Host "`nRunning the Pexip log tools script.`n"
		
        $SnapArray | ForEach-Object {
            Unprotect-PexFile -FileNameToProcess $_
			if ($AskForTicketNumber) {
            Write-Host
            Write-Warning "Please enter a ticket number to add the add the processed snap into"
            $Ticket = ($host.ui.ReadLine()).TrimEnd()
            $SnapDir = "$($SnapDir)\$Ticket"
			Write-Output "Processed snapshot along with the archive will be stored in:"$SnapDir
        }
			$BaseName = Get-Item $SnapArray | Select-Object -ExpandProperty BaseName

            # Pass a compressed snap fil$SnapFoldere and return a folder
            $SnapFolder = $_ | Expand-PexSnap
            # Pass a snap folder and return an array of support log files
            $SupportLogFiles = Get-PexLogs -Snapfolders $SnapFolder

            # If there are support log files, then parse the logs and create a log reader report
            if ($SupportLogFiles -ne $false) {
                $ConvertPexlogReturn = Convert-PexLogs -LogFiles $SupportLogFiles
                $LogReaderReturn = New-PexLogReader -SupportLogFiles $SupportLogFiles -SupportLogFolder $ConvertPexlogReturn[0]
            }
            else {
                Write-Warning "No Support Log files to process.`n"
                $ConvertPexlogReturn = $false
                $LogReaderReturn = $false
            }
            # Run generic tests on the the snap (Irregular Ping, Pulse etc).
            Test-PexLogs -Snapfolders $SnapFolder | out-null

            # Check to see if this is a Mgt node snap, and if so, run reports.
            if (Test-Path -path "$SnapDir\$BaseName\$LogDir\unified*" -PathType leaf) {
                $DBSummaryFile = New-PexSummary -Snapfolders $SnapFolder -ScriptFile $DBSummaryScript -ReportFile $DBReport -SummaryError $DBSummaryError
                $ConfHistoryFile = New-PexSummary -Snapfolders $SnapFolder -ScriptFile $ConfHistoryScript -ReportFile $ConfHistoryReport -SummaryError $ConfHistoryError
                New-PexSummary -Snapfolders $SnapFolder -ScriptFile $ConnectivityScript -ReportFile $ConnectivityReport -SummaryError $ConnectivityError | Out-Null
                New-PexSummary -Snapfolders $SnapFolder -ScriptFile $MJXScript -ReportFile $MJXReport -SummaryError $MJXError | Out-Null
            }
    
            else {
                $DBSummaryFile = $false
                $ConfHistoryFile = $false
            }

            # If there are valid files then open them open them (although might nee to wait for the log reader process to finish).
            if (($DBSummaryFile -ne $false) -and ($LogReaderReturn -ne $false) -and ($ConfHistoryFile -ne $false)) {
                Wait-Process $LogReaderReturn[1].Id -ErrorAction SilentlyContinue
                if ($null -eq (Get-Content -Path $LogReaderReturn[0])) {
                    Write-Output "Nothing to show. Perhaps check the error log file in the same folder." | Add-Content -Path $LogReaderReturn[0]
                }

                Start-Process $PathToNotepad -ArgumentList ("`"$DBSummaryFile`"", "`"$ConfHistoryFile`"", "`"$($LogReaderReturn[0])`"")
            }
            elseif (($DBSummaryFile -ne $false) -and ($ConfHistoryFile -ne $false)) {
                Start-Process $PathToNotepad -ArgumentList ("`"$DBSummaryFile`"", "`"$ConfHistoryFile`"")
            }
            elseif ($LogReaderReturn -ne $false) {
                Wait-Process $LogReaderReturn[1].Id -ErrorAction SilentlyContinue
                if ($null -eq (Get-Content -Path $LogReaderReturn[0])) {
                    Write-Output "Nothing to show. Perhaps check the error log file in the same folder." | Add-Content -Path $LogReaderReturn[0]
                }
                Start-Process $PathToNotepad -ArgumentList ("`"$($LogReaderReturn[0])`"")
            }

            # Open up Explorer in the parsed folder
            Invoke-Item "$SnapDir\$BaseName\$LogDir\$ParsedLogDir"
        }
    }

    if ($LogArray.count -gt 0) {
        Write-Host "`nProcessing Logs`n"
        $LogArray | ForEach-Object {
            Unprotect-PexFile -FileNameToProcess $_
        }
        $LogFiles = Split-PexLogs -LogFiles $LogArray
        $ConvertPexlogReturn = Convert-PexLogs -LogFiles $LogArray
        $LogReaderReturn = New-PexLogReader -SupportLogFiles $LogFiles[0] -SupportLogFolder $ConvertPexlogReturn[0]
        if ($LogReaderReturn[0] -ne $false) {
            Wait-Process $LogReaderReturn[1].Id -ErrorAction SilentlyContinue
            if ($null -eq (Get-Content -Path $LogReaderReturn[0])) {
                Write-Output "Nothing to show. Perhaps check the error log file in the same folder." | Add-Content -Path $LogReaderReturn[0]
            }
            Start-Process $PathToNotepad -ArgumentList ("`"$($LogReaderReturn[0])`"")
        }
        # Open up Explorer in the parsed folder
        Invoke-Item "$($ConvertPexlogReturn[0])\$ParsedLogDir"
    }

    if ($FolderArray.count -gt 0) {
        Write-Host "`nProcessing Folders`n"
        $FolderArray | ForEach-Object {
            if (Test-Path -path "$SnapDir\$BaseName\$LogDir\unified*" -PathType leaf) {
                $DBSummaryFile = New-PexSummary -Snapfolders $_ -ScriptFile $DBSummaryScript -ReportFile $DBReport -SummaryError $DBSummaryError
                $ConfHistoryFile = New-PexSummary -Snapfolders $_ -ScriptFile $ConfHistoryScript -ReportFile $ConfHistoryReport -SummaryError $ConfHistoryError
                New-PexSummary -Snapfolders $_ -ScriptFile $ConnectivityScript -ReportFile $ConnectivityReport -SummaryError $ConnectivityError | Out-Null
                New-PexSummary -Snapfolders $_ -ScriptFile $MJXScript -ReportFile $MJXReport -SummaryError $MJXError | Out-Null
            }
            else {
                $DBSummaryFile = $false
                $ConfHistoryFile = $false
            }
            if ($DBSummaryFile -ne $false) {
                Start-Process $PathToNotepad -ArgumentList ("`"$DBSummaryFile`"", "`"$ConfHistoryFile`"")
                Invoke-Item -Path (Split-Path -Path $DBSummaryFile)
            }
        }
    }

    if ($AnythingElseArray.count -gt 0) {
        Write-Host "`nProcessing other stuff`n"
        $AnythingElseArray | ForEach-Object {
            Unprotect-PexFile -FileNameToProcess $_
        }
    }
}
Pause
# SIG # Begin signature block
# MIIL4QYJKoZIhvcNAQcCoIIL0jCCC84CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUk5uGAJZbvquPcAtI/sYZkMfH
# 0rqggglKMIIEmTCCA4GgAwIBAgIQcaC3NpXdsa/COyuaGO5UyzANBgkqhkiG9w0B
# AQsFADCBqTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEoMCYG
# A1UECxMfQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcyBEaXZpc2lvbjE4MDYGA1UECxMv
# KGMpIDIwMDYgdGhhd3RlLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkx
# HzAdBgNVBAMTFnRoYXd0ZSBQcmltYXJ5IFJvb3QgQ0EwHhcNMTMxMjEwMDAwMDAw
# WhcNMjMxMjA5MjM1OTU5WjBMMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMdGhhd3Rl
# LCBJbmMuMSYwJAYDVQQDEx10aGF3dGUgU0hBMjU2IENvZGUgU2lnbmluZyBDQTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJtVAkwXBenQZsP8KK3TwP7v
# 4Ol+1B72qhuRRv31Fu2YB1P6uocbfZ4fASerudJnyrcQJVP0476bkLjtI1xC72Ql
# WOWIIhq+9ceu9b6KsRERkxoiqXRpwXS2aIengzD5ZPGx4zg+9NbB/BL+c1cXNVeK
# 3VCNA/hmzcp2gxPI1w5xHeRjyboX+NG55IjSLCjIISANQbcL4i/CgOaIe1Nsw0Rj
# gX9oR4wrKs9b9IxJYbpphf1rAHgFJmkTMIA4TvFaVcnFUNaqOIlHQ1z+TXOlScWT
# af53lpqv84wOV7oz2Q7GQtMDd8S7Oa2R+fP3llw6ZKbtJ1fB6EDzU/K+KTT+X/kC
# AwEAAaOCARcwggETMC8GCCsGAQUFBwEBBCMwITAfBggrBgEFBQcwAYYTaHR0cDov
# L3QyLnN5bWNiLmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMDIGA1UdHwQrMCkwJ6Al
# oCOGIWh0dHA6Ly90MS5zeW1jYi5jb20vVGhhd3RlUENBLmNybDAdBgNVHSUEFjAU
# BggrBgEFBQcDAgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgEGMCkGA1UdEQQiMCCk
# HjAcMRowGAYDVQQDExFTeW1hbnRlY1BLSS0xLTU2ODAdBgNVHQ4EFgQUV4abVLi+
# pimK5PbC4hMYiYXN3LcwHwYDVR0jBBgwFoAUe1tFz6/Oy3r9MZIaarbzRutXSFAw
# DQYJKoZIhvcNAQELBQADggEBACQ79degNhPHQ/7wCYdo0ZgxbhLkPx4flntrTB6H
# novFbKOxDHtQktWBnLGPLCm37vmRBbmOQfEs9tBZLZjgueqAAUdAlbg9nQO9ebs1
# tq2cTCf2Z0UQycW8h05Ve9KHu93cMO/G1GzMmTVtHOBg081ojylZS4mWCEbJjvx1
# T8XcCcxOJ4tEzQe8rATgtTOlh5/03XMMkeoSgW/jdfAetZNsRBfVPpfJvQcsVncf
# hd1G6L/eLIGUo/flt6fBN591ylV3TV42KcqF2EVBcld1wHlb+jQQBm1kIEK3Osgf
# HUZkAl/GR77wxDooVNr2Hk+aohlDpG9J+PxeQiAohItHIG4wggSpMIIDkaADAgEC
# AhBbwQIMscOmSL02LV/biYW7MA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xJjAkBgNVBAMTHXRoYXd0ZSBTSEEyNTYg
# Q29kZSBTaWduaW5nIENBMB4XDTE5MTAyMzAwMDAwMFoXDTIxMTAyMjIzNTk1OVow
# ZzELMAkGA1UEBhMCTk8xDTALBgNVBAgMBE9zbG8xDTALBgNVBAcMBE9zbG8xETAP
# BgNVBAoMCFBleGlwIEFTMRQwEgYDVQQLDAtFbmdpbmVlcmluZzERMA8GA1UEAwwI
# UGV4aXAgQVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLkrt6tIU7
# cQ4SCKvFLYta9A9A8QMmqaKA2/E4Isr447q/l9oweY2TBIGDCxnhTnkOtnL9fCZx
# AbOjneoDEFNF4R/SkJtdYwDWUTffuYmZ/DOuUleHOKsIly8TmAQFmJWKI0RIL4fT
# 2pPliW/Nxmzx5638c6X2vIsW1j3L5Lk34lWJ6nf+o+S2q7vhTHks1pL2/FFRhYWW
# 60Teb5e2XaVHunSk5zuggyOCxKyRAAwkf1FAl/+1AdLlLtcsCEUdt36NBvW0djRm
# J3N8GazilgswIosUWZYab3VfwWG3p+sVVwemluLbDq535D19Nv96gHi52LrhVRAp
# qIHoGYq5Jx5pAgMBAAGjggFqMIIBZjAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFFeG
# m1S4vqYpiuT2wuITGImFzdy3MB0GA1UdDgQWBBQgSp8I3Pn8a0G+1IHvOpvxYrtL
# gzArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vdGwuc3ltY2IuY29tL3RsLmNybDAO
# BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwbgYDVR0gBGcwZTBj
# BgZngQwBBAEwWTAmBggrBgEFBQcCARYaaHR0cHM6Ly93d3cudGhhd3RlLmNvbS9j
# cHMwLwYIKwYBBQUHAgIwIwwhaHR0cHM6Ly93d3cudGhhd3RlLmNvbS9yZXBvc2l0
# b3J5MFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYTaHR0cDovL3RsLnN5bWNk
# LmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL3RsLnN5bWNiLmNvbS90bC5jcnQwDQYJ
# KoZIhvcNAQELBQADggEBAFTkvegvH4KqHVI16TZgiXfIxyjAe7Z073ko2XS+8mxE
# SQ2S/NGBf7+vur8i7wRdO3zwkWwPeWXZeyITb2myImSxJJdhxi9qWi/SSh2QKXuc
# zcQ0OY6fr1io9Ug8yH5iEhB7KlHweh8/YhyKnNPsC8cfT6NPxfaA+V7kFa6/oVE+
# LQVQqXbJkH10N/MwA/ePG9u65lJ90xZChIIXP9cwNp3K0dce+V5sUVb1O5qg2pXH
# FDH0bIo0BRUOpKZ+WlvMiq6l/MJBYzKDtZbsh4150TQDfWQf1FBykqSPcVdXf7Kq
# QInJHyUJCeu1LFhozzCM+moGzg7ZgvAA2Csdoj0mpgQxggIBMIIB/QIBATBgMEwx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xJjAkBgNVBAMTHXRo
# YXd0ZSBTSEEyNTYgQ29kZSBTaWduaW5nIENBAhBbwQIMscOmSL02LV/biYW7MAkG
# BSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJ
# AzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMG
# CSqGSIb3DQEJBDEWBBQbHD82fv1qyncFop78rTZTCApprzANBgkqhkiG9w0BAQEF
# AASCAQAlR6jR8F3sYoDA5G8BTSGnxB37PsDzV34xmwCXwC3w1o668vY8PvjBV5lw
# YnCG0BE6nPu0XWikki3Z/59knx5QFrEhsalmHdxdP2uS2KWOA5EZV4dtL3J77zh9
# fSnLOy8VaAAaC9Rk0yUDhVau09WRI3+mjwtSmTp12B53ufi3abBxxZLNpm9rSUnN
# NSofYuM6uO9SpXe8UopkBBCIY2bzhnvwX70z0XhSIpUDTRcXwYtWv/9QOst0jF8O
# FYbHO/f8gvEf0IOzv+4XdOhsLCq5cSyIIapToXdjn+9LfjEnIHR45epsMbVY/ZVk
# b4phChzsTygXNjeNetW7CIopV3W7
# SIG # End signature block
