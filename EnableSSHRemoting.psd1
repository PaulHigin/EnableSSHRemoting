#
# Module manifest for module 'EnableSSHRemoting'
#

@{

RootModule = '.\EnableSSHRemoting.psm1'

ModuleVersion = '0.5'

GUID = '9eea5519-8e7b-464b-b26d-c9f2ee30fdfb'

Author = 'Microsoft Corporation'
CompanyName = 'Microsoft Corporation'
Copyright = '(c) Microsoft Corporation. All rights reserved.'

Description = '
PowerShell SSH remoting was implemented in PowerShell 6.0 but requries SSH (client) and SSHD (service) components 
to be installed.  In addition the sshd_config configuration file must be updated to define a PowerShell endpoint
as a subsystem.  Once this is done PowerShell remoting cmdlets can be used to establish a PowerShell remoting
session over SSH that works across platforms.

$session = New-PSSession -HostName LinuxComputer1 -UserName UserA -SSHTransport

There are a number of requirements that must be satisfied for PowerShell SSH based remoting:
  a. PowerShell 6.0 or greater must be installed on the system.
       Since multiple PowerShell installations can appear on a single system, a specific installation can be selected.
  b. SSH client must be installed on the system as PowerShell uses it for outgoing connections.
  c. SSHD (ssh daemon) must be installed on the system for PowerShell to receive SSH connections.
  d. SSHD must be configured with a Subsystem that serves as the PowerShell remoting endpoint.

This module exports a single cmdlet: Enable-SSHRemoting

The Enable-SSHRemoting cmdlet will do the following:
  a. Detect the underlying platform (Windows, Linux, macOS).
  b. Detect an installed SSH client, and emit a warning if not found.
  c. Detect an installed SSHD daemon, and emit a warning if not found.
  d. Accept a PowerShell (pwsh) path to be run as a remoting PowerShell session endpoint.
       Or try to use the currently running PowerShell.
  e. Update the SSHD configuration file to add a PowerShell subsystem endpoint entry.

If all of the conditions are satisfied then PowerShell SSH remoting will work to and from the local system.
'

PowerShellVersion = '6.0'

FunctionsToExport = 'Enable-SSHRemoting'

}
