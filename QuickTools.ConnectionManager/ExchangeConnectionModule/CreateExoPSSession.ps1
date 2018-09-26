$UserPath = [Environment]::GetFolderPath("UserProfile")
cd $UserPath

Write-Host -ForegroundColor Yellow ""
Write-Host -ForegroundColor Yellow "--------------------------------------------------------------------------"
Write-Host -ForegroundColor Yellow ""
Write-Host -ForegroundColor Yellow "This PowerShell module allows you to connect to Exchange Online service."
Write-Host -ForegroundColor Yellow "To connect, use: Connect-EXOPSSession -UserPrincipalName <your UPN>"
Write-Host -ForegroundColor Yellow "This PowerShell module allows you to connect Exchange Online Protection and Security & Compliance Center services also."
Write-Host -ForegroundColor Yellow "To connect, use: Connect-IPPSSession -UserPrincipalName <your UPN>"
Write-Host -ForegroundColor Yellow ""
Write-Host -ForegroundColor Yellow "To get additional information, use: Get-Help Connect-EXOPSSession, or Get-Help Connect-IPPSSession"
Write-Host -ForegroundColor Yellow ""
Write-Host -ForegroundColor Yellow "--------------------------------------------------------------------------"
Write-Host -ForegroundColor Yellow ""

<#
.Synopsis Validates a given Uri
#>

function Test-Uri
{
    [CmdletBinding()]
    [OutputType([bool])]
    Param
    (
        # Uri to be validated
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [string]
        $UriString
    )

    [Uri]$uri = $UriString -as [Uri]

    $uri.AbsoluteUri -ne $null -and $uri.Scheme -eq 'https'
}

<#
.Synopsis Override Get-PSImplicitRemotingSession function for reconnection
#>
function global:UpdateImplicitRemotingHandler()
{
    $modules = Get-Module tmp_*

    foreach ($module in $modules)
    {
        [bool]$moduleProcessed = $false
        [string] $moduleUrl = $module.Description
        [int] $queryStringIndex = $moduleUrl.IndexOf("?")

        if ($queryStringIndex -gt 0)
        {
            $moduleUrl = $moduleUrl.SubString(0,$queryStringIndex)
        }

        if ($moduleUrl.EndsWith("/PowerShell-LiveId", [StringComparison]::OrdinalIgnoreCase) -or $moduleUrl.EndsWith("/PowerShell", [StringComparison]::OrdinalIgnoreCase))
        {
            & $module { ${function:Get-PSImplicitRemotingSession} = `
            {
                param(
                    [Parameter(Mandatory = $true, Position = 0)]
                    [string]
                    $commandName
                )

                if (($script:PSSession -eq $null) -or ($script:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
                {
                    Set-PSImplicitRemotingSession `
                        (& $script:GetPSSession `
                            -InstanceId $script:PSSession.InstanceId.Guid `
                            -ErrorAction SilentlyContinue )
                }
                if (($script:PSSession -ne $null) -and ($script:PSSession.Runspace.RunspaceStateInfo.State -eq 'Disconnected'))
                {
                    # If we are handed a disconnected session, try re-connecting it before creating a new session.
                    Set-PSImplicitRemotingSession `
                        (& $script:ConnectPSSession `
                            -Session $script:PSSession `
                            -ErrorAction SilentlyContinue)
                }
                if (($script:PSSession -eq $null) -or ($script:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
                {
                    Write-PSImplicitRemotingMessage ('Creating a new Remote PowerShell session using MFA for implicit remoting of "{0}" command ...' -f $commandName)
                    $session = New-ExoPSSession -UserPrincipalName $global:UserPrincipalName -ConnectionUri $global:ConnectionUri -AzureADAuthorizationEndpointUri $global:AzureADAuthorizationEndpointUri -PSSessionOption $global:PSSessionOption -Credential $global:Credential

                    if ($session -ne $null)
                    {
                        Set-PSImplicitRemotingSession -CreatedByModule $true -PSSession $session
                    }

                    RemoveBrokenOrClosedPSSession
                }
                if (($script:PSSession -eq $null) -or ($script:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
                {
                    throw 'No session has been associated with this implicit remoting module'
                }

                return [Management.Automation.Runspaces.PSSession]$script:PSSession
            }}
        }
    }
}

<#
.Synopsis Remove broken and closed sessions
#>
function global:RemoveBrokenOrClosedPSSession()
{
    $psBroken = Get-PSSession | where-object {$_.State -like "*Broken*"}
    $psClosed = Get-PSSession | where-object {$_.State -like "*Closed*"}

    if ($psBroken.count -gt 0)
    {
        for ($index = 0; $index -lt $psBroken.count; $index++)
        {
            Remove-PSSession -session $psBroken[$index]
        }
    }

    if ($psClosed.count -gt 0)
    {
        for ($index = 0; $index -lt $psClosed.count; $index++)
        {
            Remove-PSSession -session $psClosed[$index]
        }
    }
}

###### Begin Main ######

function Connect-EXOPSSession {
    <#
        .SYNOPSIS
            To connect in other Office 365 offerings, use the following settings:
             - Office 365 operated by 21Vianet: -ConnectionURI https://partner.outlook.cn/PowerShell-LiveID -AzureADAuthorizationEndpointUri https://login.chinacloudapi.cn/common
             - Office 365 Germany: -ConnectionURI https://outlook.office.de/PowerShell-LiveID -AzureADAuthorizationEndpointUri https://login.microsoftonline.de/common
        
            - PSSessionOption accept object created using New-PSSessionOption
        .DESCRIPTION
            This PowerShell module allows you to connect to Exchange Online service
        .LINK
            https://go.microsoft.com/fwlink/p/?linkid=837645
    #>

    param(
        # Connection Uri for the Remote PowerShell endpoint
        [string] $ConnectionUri = 'https://outlook.office365.com/PowerShell-LiveId',

        # Azure AD Authorization endpoint Uri that can issue the OAuth2 access tokens
        [string] $AzureADAuthorizationEndpointUri = 'https://login.windows.net/common',

        # User Principal Name or email address of the user
        [string] $UserPrincipalName = '',

        # PowerShell session options to be used when opening the Remote PowerShell session
        [System.Management.Automation.Remoting.PSSessionOption] $PSSessionOption = $null,

        # User Credential to Logon
        [System.Management.Automation.PSCredential] $Credential = $null
    )

    # Validate parameters
    if (-not (Test-Uri $ConnectionUri))
    {
        throw "Invalid ConnectionUri parameter '$ConnectionUri'"
    }
    if (-not (Test-Uri $AzureADAuthorizationEndpointUri))
    {
        throw "Invalid AzureADAuthorizationEndpointUri parameter '$AzureADAuthorizationEndpointUri'"
    }

    try
    {
        # Cleanup old ps sessions
        Get-PSSession | Remove-PSSession

        $ExoPowershellModule = "Microsoft.Exchange.Management.ExoPowershellModule.dll";
        $ModulePath = [System.IO.Path]::Combine($PSScriptRoot, $ExoPowershellModule);

        $global:ConnectionUri = $ConnectionUri;
        $global:AzureADAuthorizationEndpointUri = $AzureADAuthorizationEndpointUri;
        $global:UserPrincipalName = $UserPrincipalName;
        $global:PSSessionOption = $PSSessionOption;
        $global:Credential = $Credential;

        Import-Module $ModulePath;
        $PSSession = New-ExoPSSession -UserPrincipalName $UserPrincipalName -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -PSSessionOption $PSSessionOption -Credential $Credential
    
        if ($PSSession -ne $null)
        {
            Import-PSSession $PSSession -AllowClobber
            UpdateImplicitRemotingHandler
        }
    }
    catch
    {
        throw $_
    }
}

function Connect-IPPSSession
{
    <#
        .SYNOPSIS
            Connect-IPPSSession -ConnectionURI https://ps.compliance.protection.outlook.com/PowerShell-LiveId -AzureADAuthorizationEndpointUri https://login.windows.net/common
            NOTE: PSSessionOption accept object created using New-PSSessionOption
                  Please add -DelegatedOrganization para name and its value (domain name) if you want manage another tenant
        .DESCRIPTION
            This cmdlet allows you to connect to Exchange Online Protection Service
    #>

    param(
        # Connection Uri for the Remote PowerShell endpoint
        [string] $ConnectionUri = 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId',

        # Azure AD Authorization endpoint Uri that can issue the OAuth2 access tokens
        [string] $AzureADAuthorizationEndpointUri = 'https://login.windows.net/common',

        # User Principal Name or email address of the user
        [string] $UserPrincipalName = '',

        # Delegated Organization Name
        [string] $DelegatedOrganization = '',

        # PowerShell session options to be used when opening the Remote PowerShell session
        [System.Management.Automation.Remoting.PSSessionOption] $PSSessionOption = $null,

        # User Credential to Logon
        [System.Management.Automation.PSCredential] $Credential = $null
    )


    [string]$newUri = $null;

    if (![string]::IsNullOrWhiteSpace($DelegatedOrganization))
    {
        [UriBuilder] $uriBuilder = New-Object -TypeName UriBuilder -ArgumentList $ConnectionUri;
        [string] $queryToAppend = "DelegatedOrg={0}" -f $DelegatedOrganization;
        if ($uriBuilder.Query -ne $null -and $uriBuilder.Query.Length -gt 0)
        {
            [string] $existingQuery = $uriBuilder.Query.Substring(1);
            $uriBuilder.Query = $existingQuery + "&" + $queryToAppend;
        }
        else
        {
            $uriBuilder.Query = $queryToAppend;
        }

        $newUri = $uriBuilder.ToString();
    }
    else
    {
       $newUri = $ConnectionUri;
    }

    Connect-EXOPSSession -ConnectionUri $newUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri -UserPrincipalName $UserPrincipalName -PSSessionOption $PSSessionOption -Credential $Credential
}