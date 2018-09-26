<# 

.DESCRIPTION 
 Use to create a new user in a hybrid environment 

.PARAMETER First
 The user's First Name

.PARAMETER Last
 The user's Last Name

.PARAMETER Initial
 The user's middle initial. Should only be one character. Leave off if user has no initial, or you do not know it.

.PARAMETER OrganizationalUnit
 The organizational unit in which to create the account.

.PARAMETER DomainController
 The Active Directory domain controller to create the account against.

.PARAMETER OrganizationalUnit
 The organizational unit in which to create the account.

.PARAMETER AddGroups
 Groups to add to the user's Active Directory account on creation. Defaults to a single entry, O365LicensedUsers, which is the QT basic licensing group.

.PARAMETER Session
 The Exchange session to use to create the Remote Mailboxes

.PARAMETER ConnectionUri
 The URI to use to connect to the Exchange server, if a session wasn't already provided.
#> 
<#PSScriptInfo

.VERSION 1.0.5

.GUID 7ad5300c-eb20-4be0-afc3-6837c13ee9b3

.AUTHOR Christopher Martin

.COMPANYNAME 

.COPYRIGHT 

.TAGS AD Exchange RemoteMailbox User

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES ActiveDirectory

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


#>

#Requires -Module ActiveDirectory

<# 

.DESCRIPTION 
 Use to create a new user in a hybrid environment 

#> 
[CmdletBinding(DefaultParameterSetName = 'NewSession')]
Param(
    [Parameter(
        Mandatory = $true,
        Position = 0,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'ExistingSession')]
    [Parameter(
        Mandatory = $true,
        Position = 0,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'NewSession')]
    [string] $First,

    [Parameter(
        Mandatory = $true,
        Position = 1,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'ExistingSession')]
    [Parameter(
        Mandatory = $true,
        Position = 1,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'NewSession')]
    [string] $Last,

    [Parameter(
        Mandatory = $false,
        Position = 2,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'ExistingSession')]
    [Parameter(
        Mandatory = $false,
        Position = 2,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'NewSession')]
    [ValidateLength(1,1)]
    [string] $Initial = "NMI",

    [Parameter(
        Mandatory = $true,
        Position = 3,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'ExistingSession')]
    [Parameter(
        Mandatory = $true,
        Position = 3,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'NewSession')]
    [string] $OrganizationalUnit,

    [Parameter(
        Mandatory = $false,
        Position = 4,
        ParameterSetName = 'ExistingSession')]
    [Parameter(
        Mandatory = $false,
        Position = 4,
        ParameterSetName = 'NewSession')]
    [string] $DomainController = (Get-ADDomainController -ErrorAction Stop | Select-Object -ExpandProperty HostName),

    [Parameter(
        Mandatory = $false,
        Position = 5,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'ExistingSession')]
    [Parameter(
        Mandatory = $false,
        Position = 5,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'NewSession')]
    [string[]] $AddGroups,

    [Parameter(
        Mandatory = $true,
        Position = 6,
        ParameterSetName = 'ExistingSession')]
    [System.Management.Automation.Runspaces.PSSession] $Session,

    [Parameter(
        Mandatory = $true,
        Position = 6,
        ParameterSetName = 'NewSession')]
    [string] $ConnectionUri
    )
    Begin
    {
        # Create a session if one wasn't provided

        function New-QTExchangeOnPremSession
        {
            [CmdletBinding()]
            Param($ConnectionUri)
    
            New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri -Authentication Kerberos -ErrorAction Stop
        }

        # Create a session if one wasn't provided

        if ($PSCmdlet.ParameterSetName -eq 'NewSession')
        {
            Write-Verbose -Message "Connecting to Exchange server at $ConnectionUri"
            # Mark session to be removed upon script completion so we don't leave artifacts behind
            $Script:KillSessionWhenDone = $true
            $Script:ActiveSession = New-QTExchangeOnPremSession -ConnectionUri $ConnectionUri -ErrorAction Stop
            Write-Verbose -Message "Connected"
        }
        else 
        {    
            $Script:KillSessionWhenDone = $false
            $Script:ActiveSession = $Session
        }
    }
    Process
    {
        $emailSuffix = ""
        $rraSuffix = ""


        function New-QTUserIdentity
        {
            [CmdletBinding()]
            Param(
                [Parameter(
                    Mandatory = $true,
                    Position = 0)]
                [string] $First,
        
                [Parameter(
                    Mandatory = $true,
                    Position = 1)]
                [string] $Last,
        
                [Parameter(
                    Mandatory = $false,
                    Position = 2)]
                [ValidateLength(1,1)]
                [string] $MiddleInitial = "NMI",

                [Parameter(
                    Mandatory = $true,
                    Position = 3)]
                [string] $EmailSuffix,
        
                [Parameter(
                    Mandatory = $true,
                    Position = 4)]
                [string] $RemoteRoutingSuffix
                )

                function samExists
                {
                    Param($sam)

                    $filter = {
                        (SamAccountName -eq $sam) -or
                        (mailNickname -eq $sam)
                        }
                    
                    return ((Get-ADUser -Filter $filter -ErrorAction Stop) -ne $null)
                }
                
                function prefixTaken
                {
                    Param($prefix, $emailSuffix, $rraSuffix)
                
                    $upn = "$($prefix)@$emailSuffix"
                    $rra = "$($prefix)@$rraSuffix"
                    $smtp = "smtp:$upn"
                    $smtpRra = "smtp:$rra"

                    $filter = {
                        (UserPrincipalName -eq $upn) -or
                        (mail -eq $upn) -or 
                        (proxyAddresses -eq $upn) -or 
                        (proxyAddresses -eq $rra) -or 
                        (proxyAddresses -eq $smtp) -or 
                        (proxyAddresses -eq $smtpRra)
                        }
                
                    return ((Get-ADUser -Filter $filter -ErrorAction Stop) -ne $null)
                
                }
                
                $userId = "$($Last)$($First.Substring(0,1))$MiddleInitial"
                
                $count = 0
                
                while (samExists -sam $userId)
                {
                    ++$count
                    $userId = "$($Last)$($First.Substring(0,1))$($MiddleInitial)$($count)"
                }
                
                $prefix = "$($First).$($Last)"
                
                $count = 1
                
                while (prefixTaken -prefix $prefix -emailSuffix $EmailSuffix -rraSuffix $RemoteRoutingSuffix)
                {
                    ++$count
                    $prefix = "$($First).$($Last)$($count)"
                }
                
                [PSCustomObject]@{
                    UPN = "$($prefix)@$emailSuffix"
                    RRA = "$($prefix)@$rraSuffix"
                    SAM = $userId
                    }
        }

        function New-QTUserMailbox
        {
            Param(
                [Parameter(
                    Mandatory = $true,
                    Position = 0)]
                [string] $First,
        
                [Parameter(
                    Mandatory = $true,
                    Position = 1)]
                [string] $Last,
        
                [Parameter(
                    Mandatory = $false,
                    Position = 2)]
                [string] $Initial = "NMI",
        
                [Parameter(
                    Mandatory = $false,
                    Position = 3)]
                [string] $OrganizationalUnit = $Script:QTDefaultNewMailboxOrganizationalUnit,
        
                [Parameter(
                    Mandatory = $true,
                    Position = 4)]
                [string] $EmailPrefix,
        
                [Parameter(
                    Mandatory = $true,
                    Position = 5)]
                [ValidateLength(1,20)]
                [string] $SamAccountName,
        
                [Parameter(
                    Mandatory = $true,
                    Position = 6)]
                [string] $Name,
        
                [Parameter(
                    Mandatory = $false,
                    Position = 7)]
                [System.Security.SecureString] $Password = (New-RandomPassword),
        
                [Parameter(
                    Mandatory = $true,
                    Position = 8)]
                [string] $EmailSuffix,
        
                [Parameter(
                    Mandatory = $true,
                    Position = 9)]
                [string] $RemoteRoutingSuffix,
        
                [Parameter(
                    Mandatory = $true,
                    Position = 9)]
                [string] $DomainController,

                $Session
                )
        
                $upn = "$($EmailPrefix)@$($EmailSuffix)"
        
                $rra = "$($EmailPrefix)@$($RemoteRoutingSuffix)"
        
                    # Do NOT specify -PrimarySmtpAddress or the Outlook client won't work for the user.
        
                $newRemoteMailboxParams = @{
                    AccountDisabled = $true
                    Password = $Password
                    OnPremisesOrganizationalUnit = $OrganizationalUnit
                    ResetPasswordOnNextLogon = $true
                    DomainController = $DomainController
                    FirstName = $First
                    LastName = $Last
                    Alias = $SamAccountName
                    SamAccountName = $SamAccountName
                    UserPrincipalName = $upn
                    RemoteRoutingAddress = $rra
                    Name = $Name
                    DisplayName = $Name
                    ErrorAction = 'Stop'
                    }

                if ($Initial -ne "NMI")
                {
                    $newRemoteMailboxParams.Add('Initials',$Initial)
                }
                
                $sb = New-Object -TypeName System.Text.StringBuilder

                [void]$sb.AppendLine('Param([Parameter(Position = 0)]$NewRemoteMailboxParams)')
                [void]$sb.AppendLine('New-RemoteMailbox @NewRemoteMailboxParams')
                
                $scriptBlock = [ScriptBlock]::Create($sb.ToString())

                Invoke-Command -Session $Session -ScriptBlock $scriptBlock -ArgumentList $newRemoteMailboxParams -ErrorAction Stop
        }

        function New-RandomPassword
        {
            [CmdletBinding()]
            Param(
                [Parameter(
                    Mandatory = $false,
                    Position = 0)]
                [int] $Length = 75,
                [switch] $AsPlainText)
            <#
            .SYNOPSIS
            Creates a 75 character random password using uppercase, lowercase, numbers, and symbols. Normally returns a SecureString, but if you use the -AsPlainText switch, it'll output as a regular string instead.

            .PARAMETER Length
            The length of the password to generate.

            .PARAMETER AsPlainText
            Output the password as a string, instead of a SecureString. Requires additional computation, as Password is created as a SecureString, then decrypted.
            #>

            $myInputString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_-<>"

            $myArray = $myInputString.ToCharArray()

            $mySecureString = New-Object -TypeName System.Security.SecureString

            for($i = 1; $i -le $Length ; $i++)
            {
                $mySecureString.AppendChar((Get-Random -InputObject $myArray))
            }

            if (!$AsPlainText)
            {
                Write-Output -InputObject $mySecureString
            }
            else
            {
                $cred = New-Object -TypeName PSCredential -ArgumentList "a",$mySecureString

                $cred.GetNetworkCredential().Password

                $mySecureString.Dispose()
            }    
        }

        # Create/Get identity information.

        $newQTUserIdentityParams = @{
            First = $First
            Last = $Last
            EmailSuffix = $emailSuffix
            RemoteRoutingSuffix = $rraSuffix
            ErrorAction = 'Stop'
            }
    
        if ($Initial -eq "NMI") 
        { 
            $name = "$Last, $First"
        }
        else
        {
            $name = "$Last, $First $Initial"
            $newQTUserIdentityParams.Add('MiddleInitial', $Initial) 
        }
        
        Write-Verbose -Message "Getting identity information..."

        $identity = New-QTUserIdentity @newQTUserIdentityParams

        $newQTUserMailboxParams = @{
            First = $First
            Last = $Last
            Initial = $Initial
            OrganizationalUnit = $OrganizationalUnit
            EmailPrefix = $identity.UPN.Split('@')[0]
            SamAccountName = $identity.SAM
            Name = $name
            Password = (New-RandomPassword)
            DomainController = $DomainController
            ErrorAction = 'Stop'
            Session = $Script:ActiveSession
            }
        
        Write-Verbose -Message "Creating mailbox..."

        # Create the mailbox

        $userMailbox = New-QTUserMailbox @newQTUserMailboxParams

        # Add any groups specified in the script
        foreach ($group in $AddGroups)
        {
            try
            {
                Write-Verbose -Message "Adding $group to $($userMailbox.SamAccountName)..."
                Add-ADGroupMember -Identity $group -Members $userMailbox.SamAccountName -Server $userMailbox.OriginatingServer -ErrorAction Stop    
            }
            catch
            {
                Write-Warning -Message $_.ToString()
                continue
            }
        }

        Write-Output -InputObject $userMailbox
        
    }
    End
    {
        # Remove session if it was created in the script
        if ($Script:KillSessionWhenDone)
        {
            Write-Verbose -Message "Removing created session..."
            $Script:ActiveSession | Remove-PSSession -Confirm:$false -ErrorAction Stop
        }

        Write-Verbose -Message "Complete."
    }












