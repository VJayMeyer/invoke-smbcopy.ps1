<#
.SYNOPSIS
    This script will target either a range of IP addesse, a specific IP address, a specific host 
    or a range of hosts with a file of a random size and if a range is specified to how many hosts in that range
    to target

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

#>

[cmdletbinding()]
param(
 
    [Parameter(Mandatory,ParameterSetName = 'IPAddress')]
    [ValidateNotNullOrEmpty()]
    [string]$IPAddress,

    [Parameter(Mandatory,ParameterSetName = 'HostName')]
    [ValidateNotNullOrEmpty()]
    [string]$HostName,
 
    [Parameter(Mandatory,ParameterSetName = 'HostRange')]
    [ValidateNotNullOrEmpty()]
    [string]$HostRange,

    [Parameter(Mandatory,ParameterSetName = 'IPAddressRange')]
    [ValidateNotNullOrEmpty()]
    [string]$IPAddressRange,
 
    [Parameter(Mandatory,ParameterSetName = 'IPAddress')]
    [parameter(Mandatory,ParameterSetName = "HostName")]
    [parameter(Mandatory,ParameterSetName = "IPAddressRange")]
    [parameter(Mandatory,ParameterSetName = "HostRange")]
    [ValidateNotNullOrEmpty()]
    [string]$TargetLocation,

    [Parameter(Mandatory,ParameterSetName = 'IPAddress')]
    [parameter(Mandatory,ParameterSetName = "HostName")]
    [parameter(Mandatory,ParameterSetName = "IPAddressRange")]
    [parameter(Mandatory,ParameterSetName = "HostRange")]
    [ValidateNotNullOrEmpty()]
    [int]$NumberOfFiles,

    [Parameter(Mandatory,ParameterSetName = 'IPAddress')]
    [parameter(Mandatory,ParameterSetName = "HostName")]
    [parameter(Mandatory,ParameterSetName = "IPAddressRange")]
    [parameter(Mandatory,ParameterSetName = "HostRange")]
    [ValidateNotNullOrEmpty()]
    [Int64]$FileSize,

    [Parameter(Mandatory,ParameterSetName = 'IPAddress')]
    [parameter(Mandatory,ParameterSetName = "HostName")]
    [parameter(Mandatory,ParameterSetName = "IPAddressRange")]
    [parameter(Mandatory,ParameterSetName = "HostRange")]
    [ValidateNotNullOrEmpty()]
    [bool]$PurgeOldTestFiles,
    
    [parameter(Mandatory,ParameterSetName = "IPAddressRange")]
    [parameter(Mandatory,ParameterSetName = "HostRange")]
    [ValidateNotNullOrEmpty()]
    [string]$NumberOfHosts,

    [Parameter(ParameterSetName = 'IPAddress')]
    [parameter(ParameterSetName = "HostName")]
    [parameter(ParameterSetName = "IPAddressRange")]
    [parameter(ParameterSetName = "HostRange")]
    [switch]$UseCredentials,

    [Parameter(ParameterSetName = 'IPAddress')]
    [parameter(ParameterSetName = "HostName")]
    [parameter(ParameterSetName = "IPAddressRange")]
    [parameter(ParameterSetName = "HostRange")]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    [Parameter(ParameterSetName = 'IPAddress')]
    [parameter(ParameterSetName = "HostName")]
    [parameter(ParameterSetName = "IPAddressRange")]
    [parameter(ParameterSetName = "HostRange")]
    [ValidateNotNullOrEmpty()]
    [string]$Password

)
# Main Script Function Library
function test-host
{
    Param([string]$HostName)
    end
    {
        try
        {
            $port = 445
            $timeout = 1000
            $tcpclient = New-Object -TypeName system.Net.Sockets.TcpClient
            $iar = $tcpclient.BeginConnect($HostName,$port,$null,$null)
            $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)
            if(!$wait)
            {
                $tcpclient.Close()
                return $false
            }
            else
            {
                # Close the connection and report the error if there is one
            
                $null = $tcpclient.EndConnect($iar)
                $tcpclient.Close()
                return $true
            }
        }
        catch 
        {
            $false 
        }  
    }
}
function create-testfile
{
    param([Int64]$FileSize)
    end
    {
        $Path = "$env:temp\dummy.tst"
        $File = [io.file]::Create($path)
        $File.SetLength($FileSize)
        $File.Close()
        return $Path
    }
}
function generate-targethostlist
{
    param([string]$HostList,[string]$HostListType, [int]$NumberOfHosts)
    end
    {
        [string[]]$Hosts = @()
        switch ($HostListType) {
           "IPAddressRange" 
           {
                # Determine The relevant IP components
                $StartAndEnd = $HostList.Split("-")
                $StartIP = $StartAndEnd[0]
                $EndIP = $StartAndEnd[1]
                $StartIPOctects = $StartIP.Split(".")
                [int]$StartOctect = $StartIPOctects[3]
                $EndIPOctects = $EndIP.Split(".")
                [int]$EndOctect = $EndIPOctects[3]
                # Build the Return Hosts Array
                [string] $StartIPOctets = $StartIPOctects[0] + "." + $StartIPOctects[1] + "." + $StartIPOctects[2]
                # Loop through each host. Test for SMB port and update Array
                do
                {
                    $HostName = "$StartIPOctets.$StartOctect"
                    if((test-host -HostName $HostName) -eq $true) {
                        $Hosts += $HostName 
                    } else {
                        Write-Warning "$HostName is offline or SMB is not enabled through the firewall"
                    }
                    $StartOctect++
                }
                until($StartOctect -eq ($EndOctect + 1))
                break
           }
           "HostRange" 
           {
                $SplitHosts = $HostList.Split(",")
                foreach($SplitHost in $SplitHosts) {
                    if((test-host -HostName $SplitHost) -eq $true) {
                        $Hosts += $SplitHost 
                    } else {
                        Write-Warning "$SplitHost is offline or SMB is not enabled through the firewall"
                    }
                }
                break
           }

        }
        $length = $Hosts.Count
        write-host $length 
        write-host $NumberOfHosts 
        # Select Random Available Hosts
        if($length -le $NumberOfHosts) {
            # Return all available hosts as there were 
                # less available then the parameter wanted including none
            return $Hosts
        } else {
            # New return array
            [string[]] $FilteredHosts = @()
            # Select a random number between 0 and the length of the array
            $x = 0
            do
            {
                $index = Get-Random -Minimum 0 -Maximum $length
                $FilteredHosts += $Hosts[$index]
                $x++
            }
            until($x -eq $NumberOfHosts)
            return $FilteredHosts
        }

        
    }
}
function purge-testfiles
{
    param([string]$Path, [string]$HostName)
    end
    {
        $Destination = "\\$HostName\$TargetLocation"
        if(Test-Path -Path $Destination) {
            Get-ChildItem -Path $Destination -File -Filter *.tst | Remove-Item -Force
        }
        else {
            Write-Warning "Files could not be purged because the path was not accessible ($Destination)"
        }
    }
}
# Start-Job Function Library
$Functions = { 
    function copy-file
    {
        param([string]$HostName,[string]$Path,[string]$TargetLocation,[bool]$UseCredentials)
        end
        {
            # Configure Destination
            $Destination = "\\$HostName\$TargetLocation"

            # Set up an authenticated channel
            if($UseCredentials -eq $true) {
                net use $Destination $UserName /USER:$Password
            }

            # Copy to host
            if(Test-Path -Path $Destination) {
                $FileName = [guid]::NewGuid();
                $Destination = "\\$HostName\$TargetLocation\$FileName.tst"
                Copy-Item -Path $Path -Destination $Destination -Force
            }

            # Close authenticated channel
            if($UseCredentials -eq $true) {
                net use $Destination $UserName /delete
            }
        }
    }
}

function action-plan-1
{
    param([string]$HostName, [Int64]$FileSize, [string]$TargetLocation, [int]$NumberOfFiles, [bool]$PurgeOldTestFiles, [bool]$UseCredentials)
    end
    {
        # Clear all existing jobs
        Remove-Job -State Failed
        Remove-Job -State Completed

        # Test Access
        if((test-host -HostName $HostName) -eq $true)
        {
            # Check and purge old test files
            if($PurgeOldTestFiles) {
                purge-testfiles -Path $TargetLocation -HostName $HostName
            }

            # Generate a test file if one doesn't exist
            $Path = create-testfile -FileSize $FileSize

            #Loop through number of files to copy
            $x = 0
            do
            {
                #Task Name
                $TaskName = [guid]::NewGuid()

                # Start a Job
                Start-Job -Name $TaskName -ScriptBlock {
                    param([string]$Path, [string]$HostName, [string]$TargetLocation)
                    # Copy File
                    copy-file -Hostname $HostName -Path $Path -TargetLocation $TargetLocation
                } -ArgumentList($Path,$HostName,$TargetLocation,$UseCredentials) -InitializationScript $Functions

                #Increment Counter
                $x++
            }
            until($x -eq $NumberOfFiles)
        }
    }
}
function action-plan-2
{
    param([string]$HostList, [Int64]$FileSize, [string]$TargetLocation, [int]$NumberOfFiles, [bool]$PurgeOldTestFiles, [string]$HostListType, [int]$NumberOfHosts, [bool]$UseCredentials)
    end
    {
        # Clear all existing jobs
        Remove-Job -State Failed
        Remove-Job -State Completed

        # Generate a test file if one doesn't exist
        $Path = create-testfile -FileSize $FileSize

        # Get all the hosts to be parsed
        $Hosts = generate-targethostlist -HostList $HostList -HostListType $HostListType -NumberOfHosts $NumberOfHosts

        #Work Through Each Host
        foreach($HostName in $Hosts)
        {
            # Write Target
            Write-Host "SUCCESS: Starting transfer jobs to $HostName" -ForegroundColor Green

            # Check and purge old test files
            if($PurgeOldTestFiles) {
                purge-testfiles -Path $TargetLocation -HostName $HostName
            }
            #Loop through number of files to copy
            $x = 0
            do
            {
                #Task Name
                $TaskName = [guid]::NewGuid()

                # Start a Job
                Start-Job -Name $TaskName -ScriptBlock {
                    param([string]$Path, [string]$HostName, [string]$TargetLocation)
                    # Copy File
                    copy-file -Hostname $HostName -Path $Path -TargetLocation $TargetLocation
                } -ArgumentList($Path,$HostName,$TargetLocation,$UseCredentials) -InitializationScript $Functions

                #Increment Counter
                $x++
            }
            until($x -eq $NumberOfFiles)
        }
    }
}

# Determine if Workgroup Authentication is valid
if ($PSBoundParameters.ContainsKey('UseCredentials')) { 
    $UseCredentials = $true
} else {
    $UseCredentials = $false
}
# Execute Action Plan 1 - IP Address
if ($PSBoundParameters.ContainsKey('IPAddress')) {
    write-host "Executing Action Plan 1"
    action-plan-1 -HostName $IPAddress `
                  -FileSize $FileSize `
                  -TargetLocation $TargetLocation `
                  -NumberOfFiles $NumberOfFiles `
                  -PurgeOldTestFiles $PurgeOldTestFiles `
                  -UseCredentials $UseCredentials
}
# Execute Action Plan 1 - Hostname
if ($PSBoundParameters.ContainsKey('HostName')) {
    write-host "Executing Action Plan 1"
    action-plan-1 -HostName $HostName `
                  -FileSize $FileSize `
                  -TargetLocation $TargetLocation `
                  -NumberOfFiles $NumberOfFiles `
                  -PurgeOldTestFiles $PurgeOldTestFiles `
                  -UseCredentials $UseCredentials
}
# Execute Action Plan 2 - IP Address Range
if ($PSBoundParameters.ContainsKey('IPAddressRange')) {
    write-host "Executing Action Plan 2"
    action-plan-2 -HostList $IPAddressRange `
                  -FileSize $FileSize `
                  -TargetLocation $TargetLocation `
                  -NumberOfFiles $NumberOfFiles `
                  -PurgeOldTestFiles $PurgeOldTestFiles `
                  -HostListType "IPAddressRange" `
                  -NumberOfHosts $NumberOfHosts `
                  -UseCredentials $UseCredentials
}
# Execute Action Plan 2 - Host Range
if ($PSBoundParameters.ContainsKey('HostRange')) {
    write-host "Executing Action Plan 2"
    action-plan-2 -HostList $HostRange `
                  -FileSize $FileSize `
                  -TargetLocation $TargetLocation `
                  -NumberOfFiles $NumberOfFiles `
                  -PurgeOldTestFiles $PurgeOldTestFiles `
                  -HostListType "HostRange" `
                  -NumberOfHosts $NumberOfHosts `
                  -UseCredentials $UseCredentials
}
