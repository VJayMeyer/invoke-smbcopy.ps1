.SYNOPSIS
    
    This script will target either a range of IP addesse, a specific IP address, a specific host 
    or a range of hosts with a file of a random size and if a range is specified to how many hosts in that range
    to target.
    
.DESCRIPTION
    
    This script will create a file of a certain size and then copy that file to the target hosts sequentially

.PARAMETER

    $IPAddress - The host to target
    $FileSize - The size of the target file
    $TargetLocation - The remaining UNC path to be used
    
    Or

    $IPAddressRange - A range of IP Addresses containing target hosts
    $FileSize - The size of the target file
    $TargetLocation - The remaining UNC path to be used
    $NumberOfHosts - The ammount of hosts to target (note. If the amount is greater than the range than the maximum in the range is used).

    Or

    $HostName - The host to target
    $FileSize - The size of the target file
    $TargetLocation - The remaining UNC path to be used

    Or

    $HostRange - A range of Hosts
    $FileSize - The size of the target file
    $TargetLocation - The remaining UNC path to be used
    $NumberOfHosts - The ammount of hosts to target (note. If the amount is greater than the range than the maximum in the range is used).


.INPUTS
    
    None.

.EXAMPLE
    
    .\Invoke-SMBCopy.ps1 -IPAddress 192.168.0.10 -FileSize 20GB -TargetLocation D$
    .\Invoke-SMBCopy.ps1 -IPAddressRange 192.168.0.10-192.168.0.20 -FileSize 20GB -TargetLocation D$ -NumberOfHosts 5
    .\Invoke-SMBCopy.ps1 -HostName Server1 -FileSize 1TB -TargetLocation D$\SomeFolder
    .\Invoke-SMBCopy.ps1 -HostRange "Server1,Server2,Server3,Server4" -FileSize 20GB -TargetLocation D$ -NumberOfHosts 2
    .\Invoke-SMBCopy.ps1 -HostRange "192.168.0.10,192.168.0.110" -FileSize 20GB -TargetLocation D$ -NumberOfHosts 2
    
.NOTES
