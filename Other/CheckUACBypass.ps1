<#
Author: Johto Robbie
License: GPLv3
#>

# Function to check current UAC level
function Check-UACLevel {
    $uacSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    if ($null -eq $uacSettings) {
        Write-Host "Unable to retrieve UAC settings."
        return
    }

    $consentPrompt = $uacSettings.ConsentPromptBehaviorAdmin
    $enableLUA = $uacSettings.EnableLUA

    Write-Host "Checking the current UAC level:"
    if ($enableLUA -eq 0) {
        Write-Host "UAC is disabled, the system is vulnerable to UAC bypass."
    } elseif ($consentPrompt -eq 0) {
        Write-Host "UAC is at its lowest level, vulnerable to UAC bypass."
    } else {
        Write-Host "UAC is properly configured."
    }
}

# Function to check scheduled tasks running with 'highest privileges'
function Check-ScheduledTasks {
    Write-Host "`nChecking Scheduled Tasks running with 'highest privileges':"
    $tasks = Get-ScheduledTask | Where-Object {$_.Settings.RunLevel -eq "Highest"}
    if ($tasks) {
        foreach ($task in $tasks) {
            Write-Host "Task: $($task.TaskName) runs with elevated privileges"
        }
    } else {
        Write-Host "No Scheduled Tasks are running with elevated privileges."
    }
}

# Function to check if registry keys have been modified for UAC bypass methods
function Check-BypassRegistryKeys {
    Write-Host "`nChecking registry keys for potential UAC bypasses:"
    # Eventvwr bypass
    CheckRegistryBypass "HKCU:\Software\Classes\mscfile\Shell\Open\command" '(default)'
    # Fodhelper bypass
    CheckRegistryBypass "HKCU:\Software\Classes\ms-settings\Shell\Open\command" '(default)'
    CheckRegistryBypass "HKCU:\Software\Classes\ms-settings\Shell\Open\command" 'DelegateExecute'
    # ComputerDefaults bypass
    CheckRegistryBypass "HKCU:\Software\Classes\ms-settings\Shell\Open\command" '(default)'
    CheckRegistryBypass "HKCU:\Software\Classes\ms-settings\Shell\Open\command" 'DelegateExecute'
    # SDCLT bypass
    CheckRegistryBypass "HKCU:\Software\Classes\Folder\shell\open\command" '(default)'
    CheckRegistryBypass "HKCU:\Software\Classes\Folder\shell\open\command" 'DelegateExecute'
    # SLUI bypass
    CheckRegistryBypass "HKCU:\Software\Classes\exefile\Shell\Open\command" '(default)'
    # DiskCleanup bypass
    CheckRegistryBypass "HKCU:\Environment" 'windir'
}

# Helper function to check registry bypass for specific keys
function CheckRegistryBypass {
    param (
        [string]$keyPath,
        [string]$valueName
    )

    try {
        $keyValue = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction Stop
        if ($null -ne $keyValue) {
            Write-Host "UAC bypass detected at ${keyPath}: $($keyValue.$valueName)"
        }
    } catch {
        Write-Host "Error accessing registry key ${keyPath}: $_"
    }
}

# Function to check if applications have 'autoElevate=true' in their manifest
function Check-AutoElevate {
    Write-Host "`nChecking applications with 'autoElevate=true':"
    $executables = Get-ChildItem -Path "C:\Windows\System32\" -Filter "*.exe" -ErrorAction SilentlyContinue

    foreach ($exe in $executables) {
        if (IsDotNetAssembly $exe.FullName) {
            try {
                $assembly = [System.Reflection.Assembly]::LoadFile($exe.FullName)
                $customAttributes = $assembly.CustomAttributes
                foreach ($attribute in $customAttributes) {
                    if ($attribute.AttributeType.Name -eq "autoElevate") {
                        Write-Host "Application with 'autoElevate=true' detected: $($exe.FullName)"
                    }
                }
            } catch {
                Write-Host "Error processing $($exe.FullName): $_"
            }
        } else {
            Write-Host "Skipping non-.NET assembly: $($exe.FullName)"
        }
    }
}

# Function to check services running with LocalSystem privileges
function Check-Services {
    Write-Host "`nChecking services running with LocalSystem privileges:"
    $services = Get-WmiObject -Query "SELECT * FROM Win32_Service WHERE StartName='LocalSystem' AND (StartMode='Auto' OR StartMode='Manual')" -ErrorAction SilentlyContinue
    if ($services) {
        foreach ($service in $services) {
            Write-Host "Service: $($service.DisplayName) is running with LocalSystem privileges"
        }
    } else {
        Write-Host "No services are running with LocalSystem privileges."
    }
}

# Function to check for processes with UIAccess flag set
function Check-UIAccessProcesses {
    $uiAccessProcesses = Get-WmiObject Win32_Process | Where-Object {
        try {
            $_.GetOwner().User -eq 'SYSTEM' -and $_.CommandLine -like '*UIAccess=true*'
        } catch {
            Write-Host "Error getting owner for process ID $($_.ProcessId): $_"
            $false  
        }
    }

    if ($uiAccessProcesses) {
        Write-Host "Processes with UIAccess flag set:"
        foreach ($process in $uiAccessProcesses) {
            Write-Host "Process Name: $($process.Name) - PID: $($process.ProcessId) - Command Line: $($process.CommandLine)"
        }
    } else {
        Write-Host "No processes with UIAccess flag found."
    }
}

# Function to check for DLL hijacking
function Check-DllHijacking {
    $hijackedDlls = @("comctrl32.dll", "dismcore.dll", "wow64log.dll")
    $system32Path = "C:\Windows\System32"

    foreach ($dll in $hijackedDlls) {
        $dllPath = Join-Path -Path $system32Path -ChildPath $dll
        if (Test-Path $dllPath) {
            Write-Host "Potential DLL hijacking detected: $dllPath"
        }
    }
}

# Function to check for registry modifications
function Check-RegistryModifications {
    $registryPaths = @(
        "HKCU:\Software\Classes\ms-settings\shell\open\command",
        "HKCU:\Environment"
    )

    foreach ($path in $registryPaths) {
        # Accessing the "(default)" property safely
        try {
            $defaultValue = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object -ExpandProperty '(default)' -ErrorAction Stop
            if ($null -ne $defaultValue) {
                Write-Host "Registry modification detected at ${path}: ${defaultValue}"
            }
        } catch {
            Write-Host "Error accessing registry key ${path}: $_"
        }
    }
}

# Function to check if the user is an administrator but is still running with Medium Integrity Level
function Check-MediumIntegrityLevel {
    $integrityLevel = (whoami /groups | Select-String 'Mandatory Label\.*Medium').Matches.Value
    if ($integrityLevel) {
        Write-Host "`nWarning: The user is in the Administrator group but running with Medium Integrity Level. UAC bypass may be required to elevate to High Integrity."
    }
}

# Function to check for eventvwr.exe autoElevate setting
function Check-EventvwrAutoElevate {
    Write-Host "`nChecking for eventvwr.exe autoElevate setting:"
    $eventvwrPath = Get-Command eventvwr.exe | Select-Object -ExpandProperty Source
    if ($eventvwrPath) {
        Write-Host "Eventvwr.exe located at: $eventvwrPath"
        try {
            # Download strings64.exe from https://learn.microsoft.com/en-us/sysinternals/downloads/strings
            $autoElevateCheck = & "C:\Path\To\strings64.exe" -accepteula $eventvwrPath | Select-String 'autoElevate' -Quiet
            if ($autoElevateCheck) {
                Write-Host "AutoElevate=true is set for eventvwr.exe, potential UAC bypass vector."
            } else {
                Write-Host "AutoElevate setting not found for eventvwr.exe."
            }
        } catch {
            Write-Host "Error checking autoElevate for eventvwr.exe: $_"
        }
    } else {
        Write-Host "Eventvwr.exe not found on this system."
    }
}

# Helper function to check if a file is a .NET assembly
function IsDotNetAssembly {
    param ([string]$filePath)

    try {
        [System.Reflection.Assembly]::LoadFile($filePath) | Out-Null
        return $true
    } catch {
        return $false
    }
}

Write-Host "Starting UAC Bypass Detection..."
Check-UACLevel
Check-ScheduledTasks
Check-BypassRegistryKeys
Check-AutoElevate
Check-Services
Check-UIAccessProcesses
Check-DllHijacking
Check-RegistryModifications
Check-MediumIntegrityLevel
Check-EventvwrAutoElevate
Write-Host "`nUAC Bypass Detection completed."
