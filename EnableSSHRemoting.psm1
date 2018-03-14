##
## Enable-SSHRemoting Prototype
##

class PlatformInfo
{
    [bool] $isCoreCLR
    [bool] $isLinux
    [bool] $isOSX
    [bool] $isWindows

    [bool] $isAdmin

    [bool] $isUbuntu
    [bool] $isUbuntu14
    [bool] $isUbuntu16
    [bool] $isCentOS
    [bool] $isFedora
    [bool] $isOpenSUSE
    [bool] $isOpenSUSE13
    [bool] $isOpenSUSE42_1
    [bool] $isRedHatFamily
}

function DetectPlatform
{
    param (
        [ValidateNotNull()]
        [PlatformInfo] $PlatformInfo
    )

    try 
    {
        $Runtime = [System.Runtime.InteropServices.RuntimeInformation]
        $OSPlatform = [System.Runtime.InteropServices.OSPlatform]

        $platformInfo.isCoreCLR = $true
        $platformInfo.isLinux = $Runtime::IsOSPlatform($OSPlatform::Linux)
        $platformInfo.isOSX = $Runtime::IsOSPlatform($OSPlatform::OSX)
        $platformInfo.isWindows = $Runtime::IsOSPlatform($OSPlatform::Windows)
    } 
    catch 
    {
        $platformInfo.isCoreCLR = $false
        $platformInfo.isLinux = $false
        $platformInfo.isOSX = $false
        $platformInfo.isWindows = $true
    }

    if ($platformInfo.isWindows)
    {
        $platformInfo.isAdmin = ([System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole( `
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if ($platformInfo.isLinux)
    {
        $LinuxInfo = Get-Content /etc/os-release -Raw | ConvertFrom-StringData

        $platformInfo.isUbuntu = $LinuxInfo.ID -match 'ubuntu'
        $platformInfo.isUbuntu14 = $platformInfo.isUbuntu -and ($LinuxInfo.VERSION_ID -match '14.04')
        $platformInfo.isUbuntu16 = $platformInfo.isUbuntu -and ($LinuxInfo.VERSION_ID -match '16.04')
        $platformInfo.isCentOS = ($LinuxInfo.ID -match 'centos') -and ($LinuxInfo.VERSION_ID -match '7')
        $platformInfo.isFedora = ($LinuxInfo.ID -match 'fedora') -and ($LinuxInfo.VERSION_ID -ge '24')
        $platformInfo.isOpenSUSE = $LinuxInfo.ID -match 'opensuse'
        $platformInfo.isOpenSUSE13 = $platformInfo.isOpenSUSE -and ($LinuxInfo.VERSION_ID -match '13')
        $platformInfo.isOpenSUSE42_1 = $platformInfo.isOpenSUSE -and ($LinuxInfo.VERSION_ID -match '42.1')
        $platformInfo.isRedHatFamily = $platformInfo.isCentOS -or $platformInfo.isFedora -or $platformInfo.isOpenSUSE
    }
}

class SSHClientInfo
{
    [bool] $exists = $false
    [string] $cmdName = ""
    [string] $installPath = ""

    SSHClientInfo()
    {
        [System.Management.Automation.CommandInfo] $cmdInfo = Get-Command ssh 2>$null
        if ($cmdInfo -ne $null)
        {
            $this.exists = $true
            $this.installPath = [System.IO.Path]::GetDirectoryName($cmdInfo.Path)
            $this.cmdName = [System.IO.Path]::GetFileName($cmdInfo.Path)
        }
    }
}

class SSHServerInfo
{
    [PlatformInfo] $platformInfo
    [bool] $exists = $false
    [bool] $isServiceRunning = $false
    [string] $cmdName = ""
    [string] $installPath = ""

    SSHServerInfo(
        [PlatformInfo] $platInfo)
    {
        $this.platformInfo = $platInfo

        [System.Management.Automation.CommandInfo] $cmdInfo = Get-Command sshd 2> $null
        if ($cmdInfo -ne $null)
        {
            $this.exists = $true
            $this.installPath = [System.IO.Path]::GetDirectoryName($cmdInfo.Path)
            $this.cmdName = [System.IO.Path]::GetFileName($cmdInfo.Path)
        }
        else
        {
            return
        }

        # Is service running
        if ($this.platformInfo.isWindows)
        {
            $service = Get-Service sshd 2>$null
            if ($service -ne $null)
            {
                $this.isServiceRunning = ($service.Status -match "Running")
            }
        }
        else
        {
            if ((Get-Command service 2>$null) -ne $null)
            {
                $sshResults = service ssh status
                $status = $sshResults | ? { $_ -like '*start/running*' }
                $this.isServiceRunning = ($status -ne $null)
            }
            elseif ((Get-Command systemctl 2>$null) -ne $null)
            {
                $sshResults = systemctl status ssh
                $status = $sshResults | ? { $_ -like '*Active: active (running)*' }
                $this.isServiceRunning = ($status -ne $null)
            }
            else
            {
                Write-Error "Unable to get SSHD service status, neither 'service' or 'systemctl' commands are available"
            }
        }
    }

    RestartService()
    {
        if ($this.platformInfo.isWindows)
        {
            Restart-Service sshd
        }
        else
        {
            if ((Get-Command service 2>$null) -ne $null)
            {
                service ssh restart
            }
            elseif ((Get-Command systemctl 2>$null) -ne $null)
            {
                systemctl restart ssh
            }
            else
            {
                Write-Error "Unable to restart SSHD service, neither 'service' or 'systemctl' commands are available"
            }
        }
    }
}

class SSHRemotingConfig
{
    [PlatformInfo] $platformInfo
    [string] $psSubSystemPath = ""
    [string[]] $psSubSystemArgs = @()
    [string] $configFilePath = ""
    [bool] $configFileExists
    [bool] $pubkeyAuthentication
    [bool] $passwordAuth = $true
    [int] $psSubsystemCount = 0
    $configComponents = @()

    SSHRemotingConfig(
        [PlatformInfo] $platInfo)
    {
        $this.platformInfo = $platInfo
        $sshServerInfo = [SSHServerInfo]::new($this.platformInfo)
        if ($sshServerInfo.exists)
        {
            $this.ParseSSHRemotingConfig($sshServerInfo)
        }
    }

    [string[]] SplitConfigLine([string] $line)
    {
        $line = $line.Trim()
        $lineLength = $line.Length
        $rtnStrArray = [System.Collections.Generic.List[string]]::new()

        for ($i=0; $i -lt $lineLength; )
        {
            $startIndex = $i
            while (($i -lt $lineLength) -and ($line[$i] -ne " ") -and ($line[$i] -ne "`t")) { $i++ }
            $rtnStrArray.Add($line.Substring($startIndex, ($i - $startIndex)))
            while (($i -lt $lineLength) -and ($line[$i] -eq " ") -or ($line[$i] -eq "`t")) { $i++ }
        }

        return $rtnStrArray.ToArray()
    }

    ParseSSHRemotingConfig(
        [SSHServerInfo] $sshdInfo)
    {
        if (! $sshdInfo.exists)
        {
            Write-Error "Cannot parse the sshd_config file because the ssh server installation does not exist"
            return
        }

        if ($sshdInfo.platformInfo.isWindows)
        {
            $this.configFilePath = Join-Path $sshdInfo.installPath "sshd_config"
        }
        elseif ($sshdInfo.platformInfo.isLinux)
        {
            $this.configFilePath = Join-Path "/etc/ssh" "sshd_config"
        }
        else
        {
            Write-Error "Unsupported platform"
            return
        }

        $this.configFileExists = Test-Path $this.configFilePath

        if (! $this.configFileExists)
        {
            Write-Warning "Cannot find the sshd_config file in the ssh server installation path: $($this.configFilePath)"
            return
        }

        [string[]] $contents = Get-Content -Path $this.configFilePath
        foreach ($line in $contents)
        {
            $components = $this.SplitConfigLine($line)
            $this.configComponents += @{ Line = $line; Components = $components }

            if (($components[0] -eq "Subsystem") -and ($components[1] -eq "powershell"))
            {
                $this.psSubsystemCount++
                $this.psSubSystemPath = $components[2]
                for ($i=3; $i -lt $components.Count; $i++)
                {
                    $this.psSubSystemArgs += $components[$i]
                }
            }
            elseif ($components[0] -eq "PasswordAuthentication")
            {
                $this.passwordAuth = ($components[1] -eq "yes")
            }
            elseif ($components[0] -eq "PubkeyAuthentication")
            {
                $this.pubkeyAuthentication = ($components[1] -eq "yes")
            }
        }
    }

    UpdateConfig(
        [string]    $powerShellPath,
        [hashtable] $allowPasswordAuth,
        [hashtable] $allowPublicKeyAuth,
        [bool]      $backupConfigFile)
    {
        #
        # Update and re-write config file with existing settings plus new PowerShell remoting settings
        #

        # Subsystem
        [System.Collections.Generic.List[string]] $newContents = [System.Collections.Generic.List[string]]::new()
        $psSubSystemEntry = "Subsystem       powershell {0} {1} {2} {3}" -f $powerShellPath, "-SSHS", "-NoProfile", "-NoLogo"
        $subSystemAdded = $false

        # Password Auth
        if ($allowPasswordAuth.Message -ne "Use existing")
        {
            $passAuthEntry = "PasswordAuthentication {0}" -f $(if ($allowPasswordAuth.Allow) { "yes" } else { "no" })
            $addPassAuthEntry = $true
        }
        else
        {
            $addPassAuthEntry = $false
            $passAuthEntry = ""
        }

        # PublicKey Auth
        if ($allowPublicKeyAuth.Message -ne "Use existing")
        {
            $pubkeyEntry = "PubKeyAuthentication {0}" -f $(if ($allowPublicKeyAuth.Allow) { "yes" } else { "no" })
            $addPubKeyAuth = $true
        }
        else
        {
            $pubkeyEntry = ""
            $addPubKeyAuth = $false
        }

        foreach ($lineItem in $this.configComponents)
        {
            $line = $lineItem.Line
            $components = $lineItem.Components

            if ($components[0] -eq "SubSystem")
            {
                if (! $subSystemAdded)
                {
                    # Add new powershell subsystem entry
                    $newContents.Add($psSubSystemEntry)
                    $subSystemAdded = $true
                }

                if ($components[1] -eq "powershell")
                {
                    # Remove all existing powershell subsystem entries
                    continue
                }

                # Include existing subsystem entries.
                $newContents.Add($line)
            }
            elseif ($components[0] -match "PasswordAuthentication")
            {
                if ($addPassAuthEntry)
                {
                    # Replace existing entry
                    $addPassAuthEntry = $false
                    $newContents.Add($passAuthEntry)
                }
                else
                {
                    $newContents.Add($line)
                }
            }
            elseif ($components[0] -match "PubkeyAuthentication")
            {
                if ($addPubKeyAuth)
                {
                    # Replace existing entry
                    $addPubKeyAuth = $false
                    $newContents.Add($pubkeyEntry)
                }
                else
                {
                    $newContents.Add($line)
                }
            }
            else
            {
                # Include all other configuration lines
                $newContents.Add($line)
            }
        }

        if (! $subSystemAdded)
        {
            $newContents.Add($psSubSystemEntry)
        }

        if ($addPassAuthEntry)
        {
            $newContents.Add($passAuthEntry)
        }

        if ($addPubKeyAuth)
        {
            $newContents.Add($pubkeyEntry)
        }

        if ($backupConfigFile)
        {
            # Copy existing file to a backup version
            $uniqueName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName())
            $backupFilePath = $this.configFilePath + "_backup_" + $uniqueName
            Copy-Item -Path $this.configFilePath -Destination $backupFilePath
        }

        Set-Content -Path $this.configFilePath -Value $newContents.ToArray()
    }
}

function CheckPowerShellVersion
{
    param (
        [string] $FilePath
    )

    if (! (Test-Path $FilePath))
    {
        throw "CheckPowerShellVersion failed with invalid path: $FilePath"
    }

    $commandToExec = "& '$FilePath' -noprofile -noninteractive -c '`$PSVersionTable.PSVersion.Major'"
    $sb = [scriptblock]::Create($commandToExec)

    $psVersionMajor = 0
    try
    {
        $psVersionMajor = [int] (& $sb) 2>$null
        Write-Verbose ""
        Write-Verbose "CheckPowerShellVersion: $psVersionMajor for FilePath: $FilePath"
    }
    catch { }

    if ($psVersionMajor -ge 6)
    {
        return $true
    }
    else
    {
        return $false
    }
}


##
## Enable-SSHRemoting
##
function Enable-SSHRemoting
{
    [CmdletBinding()]
    param (
        [string] $PowerShellFilePath,
        [switch] $AllowPasswordAuthentication,
        [switch] $AllowPublicKeyAuthentication,
        [switch] $BackupConfigFile,
        [switch] $Force
    )

    if (! [string]::IsNullOrEmpty($PowerShellFilePath))
    {
        if (! (Test-Path $PowerShellFilePath))
        {
            throw "The provided PowerShell file path is invalid: $PowerShellFilePath"
        }

        if (! (CheckPowerShellVersion $PowerShellFilePath))
        {
            throw "The provided PowerShell file path is an unsupported version of PowerShell.  PowerShell version 6.0 or greater is required."
        }
    }
    else
    {
        Write-Warning "No PowerShellFilePath parameter argument was provided."
        Write-Warning "Checking the current pwsh.exe returned from Get-Command"

        # Try built-in version
        $PowerShellFilePath = Get-Command -Name pwsh 2>$null | % Source
        if (! $PowerShellFilePath -or ! (CheckPowerShellVersion $PowerShellFilePath))
        {
            throw "Unable to find a useable PowerShell (pwsh.exe) version for SSH remoting endpoint. SSH remoting is only supported for PowerShell version 6.0 and higher."
        }

        Write-Warning "Using PowerShell at this path for SSH remoting endpoint:"
        Write-Warning "$PowerShellFilePath"
    }

    Write-Verbose ""
    Write-Verbose "##############################################"
    Write-Verbose "Selected PowerShell for SSH remoting endpoint:"
    Write-Verbose "$PowerShellFilePath"
    Write-Verbose "##############################################"
    Write-Verbose ""

    # Detect platform
    $platformInfo = [PlatformInfo]::new()
    DetectPlatform $platformInfo
    Write-Verbose "Platform information"
    Write-Verbose "$($platformInfo | Out-String)"
    Write-Verbose ""

    # Detect SSH client installation
    $sshClientInfo = [SSHClientInfo]::new()
    Write-Verbose "Initial SSH client information"
    Write-Verbose "$($sshClientInfo | Out-String)"
    Write-Verbose ""

    # Detect SSH server installation
    $sshServerInfo = [SSHServerInfo]::new($platformInfo)
    Write-Verbose "Initial SSH server information"
    Write-Verbose "$($sshServerInfo | Out-String)"
    Write-Verbose ""

    # Install SSH as needed
    if (! $sshClientInfo.exists)
    {
        # TODO: Automate downloading and installing SSH client
        throw "SSH client does not exist on this machine.  Find and install SSH for this platform before continuing."
    }
    if (! $sshServerInfo.exists)
    {
        # TODO: Automate downloading and installing SSHD server
        throw "SSHD server component does not exist on this machine.  Find and install SSHD for this platform before continuing."
    }

    # Configure SSH server as needed
    $sshdConfig = [SSHRemotingConfig]::new($platformInfo)

    # Report SSHD server settings
    if (! $sshdConfig.configFileExists)
    {
        Write-Output ""
        Write-Warning "Unable to find the sshd_config configuration file needed to configure SSH PowerShell remoting."
        Write-Warning "The configuration file is expected to be at this location: $($sshdConfig.configFilePath)."
        throw "Missing sshd_config file. PowerShell SSH endpoint configuration cannot proceed."
    }

    Write-Verbose ""
    Write-Verbose "###############################"
    Write-Verbose "Current SSH server settings"
    Write-Verbose "###############################"

    Write-Verbose ""
    Write-Verbose "Configuration File Location:"
    Write-Verbose "$($sshdConfig.configFilePath)"

    Write-Verbose ""
    Write-Verbose "Password Authentication Enabled: $(if ($sshdConfig.passwordAuth) { "Yes" } else { "No" })"

    Write-Verbose ""
    Write-Verbose "Public Key Authentication Enabled: $(if ($sshdConfig.pubkeyAuthentication) { "Yes" } else { "No" })"

    if ($sshdConfig.psSubsystemCount -gt 1)
    {
        Write-Output ""
        Write-Verbose "PowerShell Subsystem:"
        Write-Verbose "$($sshdConfig.psSubSystemPath)"
        Write-Verbose ""
        Write-Warning "One or more PowerShell remoting subsystems were found in the SSHD configuration file."
        Write-Warning "These endpoint subsystem entries will be replaced with the currently chosen PowerShell version."
    }

    $hPasswordAuth = @{
        Allow = $false;
        Message = "Use existing"
    }
    if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("AllowPasswordAuthentication"))
    {
        $hPasswordAuth.Allow = $AllowPasswordAuthentication
        $hPasswordAuth.Message = "$(if ($AllowPasswordAuthentication) { "Yes" } else { "No" })"
    }

    $hPubKeyAuth = @{
        Allow = $false;
        Message = "Use existing"
    }
    if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("AllowPublicKeyAuthentication"))
    {
        $hPubKeyAuth.Allow = $AllowPublicKeyAuthentication
        $hPubKeyAuth.Message = "$(if ($AllowPublicKeyAuthentication) { "Yes" } else { "No" })"
    }

    Write-Output ""
    Write-Output "###############################"
    Write-Output "Configuring SSH server settings"
    Write-Output "###############################"
    Write-Output "SSHD configuration file path: $($sshdConfig.configFilePath)"
    Write-Output "PowerShell endpoint file path: $PowerShellFilePath"
    Write-Output "Password Authentication: $($hPasswordAuth.Message)"
    Write-Output "User Public Key Authentication: $($hPubKeyAuth.Message)"
    Write-Output "Back up configuration file: $(if ($BackupConfigFile) { "Yes" } else { "No" })"
    Write-Output "Force sshd service configuration update: $(if ($Force) { "Yes" } else { "No" })"

    $shouldContinue = $Force
    if (! $shouldContinue)
    {
        $shouldContinue = $PSCmdlet.ShouldContinue("The SSHD service configuration file (sshd_config) will now be updated to enable PowerShell remoting over SSH. Do you wish to continue?", "Enable-SSHRemoting")
    }

    if ($shouldContinue)
    {
        Write-Output ""
        Write-Output "Updating configuration file"
        $sshdConfig.UpdateConfig(
            $PowerShellFilePath,
            $hPasswordAuth,
            $hPubKeyAuth,
            $BackupConfigFile)

        Write-Output ""
        Write-Output "Restarting SSHD service"
        $sshServerInfo.RestartService()
    }
}

function Test-SSHRemoting
{
    # TODO: Implement
    throw [System.Management.Automation.PSNotImplementedException]::new("This has not yet been implemented")
}
