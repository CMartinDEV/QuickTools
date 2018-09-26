# Non-exported helper functions

function Get-ModuleManifestPrivateData 
{ 
        [CmdletBinding()]
        Param()
    
        return $MyInvocation.MyCommand.Module.PrivateData 
    }
    
function Test-SessionConfigurationStore
{
        [CmdletBinding()]
        Param(
            [Parameter(
                Mandatory = $true,
                Position = 0)]
            [System.Collections.Hashtable] $SessionConfigurationStore
            )
    
        [System.Collections.ArrayList] $expectedKeys = @(
            'ExchangeOnPremisesConnectionUri',
            'ExchangeOnlineConnectionUri',
            'ExchangeComplianceConnectionUri',
            'UseMfaByDefault'
            )
    
        [System.Collections.ArrayList] $missingKeys = @()
        
        $ExpectedKeys | Where-Object -FilterScript { !$SessionConfigurationStore.ContainsKey($_) } | ForEach-Object -Process { $null = $missingKeys.Add($_) }
    
        if (($missingKeys | Measure-Object).Count -gt 0)
        {
            return [PSCustomObject]@{
                Passed = $false
                ErrorMessage = "Missing configuration key(s) - $([string]::Join(', ', $missingKeys))"
                RecommendedAction = 'Add missing keys to the module manifest Private Data section.'
                }
        }
    
        try
        {
            
            $onlineConnectionUri = $SessionConfigurationStore['ExchangeOnlineConnectionUri']
            $complianceConnectionUri = $SessionConfigurationStore['ExchangeComplianceConnectionUri']
            $useMfaByDefault = $SessionConfigurationStore['UseMfaByDefault']
    
            # Only validating that these keys are there for now.
            $onPremisesConnectionUri = $SessionConfigurationStore['ExchangeOnPremisesConnectionUri']
        }
        catch
        {
            return [PSCustomObject]@{
                Passed = $false
                ErrorMessage = [string]$_
                RecommendedAction = 'Check module Private Data formatting'
                }
        }
    
        if (($onlineConnectionUri -notlike 'https*') -or ($complianceConnectionUri -notlike 'https*'))
        {
            return [PSCustomObject]@{
                Passed = $false
                ErrorMessage = 'Credentials would be sent in plain text over regular http connection. Aborting.'
                RecommendedAction = 'Use https to connect to Exchange Online and Compliance endpoints.'
                }
        }
    
        if ($useMfaByDefault -notin @($true,$false))
        {
            return [PSCustomObject]@{
                Passed = $false
                ErrorMessage = "UseMfaByDefault key not valid."
                RecommendedAction = 'Set UseMfaByDefault key to $true or $false'
                }
        }
    
        return [PSCustomObject]@{ Passed = $true }
    }
    
function Export-ConnectionManagerModuleMember
{
        # This would be a good spot to check roles before exporting module members.
        # I started this implementation by checking for modules with Get-Module -ListAvailable, but it was very slow. This is much faster.
    
        function Test-IsModuleAvailable
        {
            Param($Name)
    
            $commands = Get-Command -Module $Name -ErrorAction SilentlyContinue
            if ($commands -eq $null) { return $false }
            else { return $true }
        }
    
    
        # Exchange session cmdlets are downloaded directly from the server, so they're always exported.
        [System.Collections.ArrayList] $functionsToExport = @('New-ExchangeSession','Connect-ExchangeSession')
        [System.Collections.ArrayList] $aliasesToExport = @()
    
        # If MSOnline module isn't installed, Connect-MsolService will fail. Not a strict requirement, though a suggestion. Warning message will run if command isn't exported.
    
        if (Test-IsModuleAvailable -Name MSOnline) 
        {  
            $null = $functionsToExport.Add('Connect-QTMsolService') 
        }
        else
        {
            Write-Warning -Message 'MSOnline module not found, so Connect-MsolService will not be exported.'
        }
    
        if (Test-IsModuleAvailable -Name 'AzureRM.Profile') 
        {  
            $null = $functionsToExport.Add('Add-QTAzureRmAccount') 
            $null = $aliasesToExport.Add('Login-QTAzureRmAccount')
        }
        else
        {
            Write-Warning -Message 'AzureRm.Profile module not found, so Add-AzureRmAccount and Login-AzureRmAccount alias will not be exported.' 
        }
    
        Export-ModuleMember -Function $functionsToExport -Alias $aliasesToExport
    }
    
    # Exported functions
    
# Exported Functions
    
function New-QTExchangeSession
{
        [CmdletBinding()]
        Param(
            [Parameter(
                Mandatory = $true,
                Position = 0)]
            [ValidateSet('Online','OnPremises','Compliance')]
            [string] $TargetEnvironment,
    
            [Parameter(
                Mandatory = $false,
                Position = 1)]
            [PSCredential] $Credential = ([PSCredential]::Empty),
    
            [switch] $UseMfa
            )
    
        if (($TargetEnvironment -eq 'OnPremises') -and $UseMfa)
        {
            Write-Error -Exception (New-Object -TypeName System.NotImplementedException) -Message "Multi-Factor Authentication is not currently supported for on-Premises connections to Exchange through this module at this time." -RecommendedAction "Try running the command with the -UseMfa switch." -ErrorAction Stop
        }
    
        Write-Verbose -Message "Targeting the $TargetEnvironment environment"

        $params = @{
            ConfigurationName = 'Microsoft.Exchange'
            ErrorAction = 'Stop'
            }
    
        if ($TargetEnvironment -eq 'Online')
        {
            if ($UseMfa -or $Script:ModuleManifestConfigurationData['UseMfaByDefault'])
            {
                New-ExoPSSession -ErrorAction Stop
                return
            }
    
            Write-Verbose -Message "Connecting to $($Script:ModuleManifestConfigurationData['ExchangeOnlineConnectionUri'])"
    
            if ($Credential -eq ([PSCredential]::Empty))
            {
                $Credential = Get-Credential -Message "Enter your credential to connect to Exchange Online"
            }
    
            Write-Verbose -Message "Connecting as $($Credential.UserName)"
    
            $params.Add('Credential', $Credential)
            $params.Add('Authentication', 'Basic')
            $params.Add('AllowRedirection', $true)
            $params.Add('ConnectionUri', $Script:ModuleManifestConfigurationData['ExchangeOnlineConnectionUri'])
        }
        elseif ($TargetEnvironment -eq 'OnPremises')
        {
            Write-Verbose -Message "Connecting as $($env:USERNAME)"
            Write-Verbose -Message "Connecting to $($Script:ModuleManifestConfigurationData['ExchangeOnPremisesConnectionUri'])"
    
            if ($Credential -ne ([PSCredential]::Empty))
            {
                $params.Add('Credential', $Credential)
                Write-Verbose -Message "Connecting as $($Credential.UserName)"
            }
            else
            {
                Write-Verbose -Message "Connecting as $env:USERNAME"
            }
    
            $params.Add('ConnectionUri', $Script:ModuleManifestConfigurationData['ExchangeOnPremisesConnectionUri'])
            $params.Add('Authentication', 'Kerberos')
        }
        elseif ($TargetEnvironment -eq 'Compliance')
        {
            Write-Verbose -Message "Connecting to $($Script:ModuleManifestConfigurationData['ExchangeComplianceConnectionUri'])"
    
            if ($UseMfa -or $Script:ModuleManifestConfigurationData['UseMfaByDefault'])
            {
                New-ExoPSSession -ConnectionUri $Script:ModuleManifestConfigurationData['ExchangeComplianceConnectionUri'] -ErrorAction Stop
                return
            }
    
            if ($Credential -eq ([PSCredential]::Empty))
            {
                $Credential = Get-Credential -Message "Enter your credential to connect to Exchange Online"
            }
    
            Write-Verbose -Message "Connecting as $($Credential.UserName)"
    
            $params.Add('Credential', $Credential)
            $params.Add('Authentication', 'Basic')
            $params.Add('AllowRedirection', $true)
            $params.Add('ConnectionUri', $Script:ModuleManifestConfigurationData['ExchangeComplianceConnectionUri'])
        }
        else
        {
            Write-Error -Exception (New-Object -TypeName System.NotImplementedException -ArgumentList "Target Environment $TargetEnvironment has not been implemented yet.") -Message "Target Environment $TargetEnvironment has not been implemented yet." -RecommendedAction "Contact the developers." -Category NotImplemented -TargetObject $TargetEnvironment -ErrorAction Stop
        }
    
        New-PSSession @params
    }
    
function Connect-QTExchangeSession
{
        [CmdletBinding()]
        Param(
            [Parameter(
                Mandatory = $true,
                Position = 0)]
            [ValidateSet('Online','OnPremises','Compliance')]
            [string] $TargetEnvironment,
    
            [Parameter(
                Mandatory = $false,
                Position = 1)]
            [PSCredential] $Credential = ([PSCredential]::Empty),
    
            [Parameter(
                Mandatory = $false,
                Position = 2)]
            [string[]] $CommandName = $null,
    
            [switch] $AllowClobber,
    
            [switch] $UseMfa
            )
    
        $session = New-ExchangeSession -TargetEnvironment $TargetEnvironment -UseMfa:$UseMfa -ErrorAction Stop
    
        $params = @{
            Session = $session
            ErrorAction = 'Stop'
            WarningAction = 'SilentlyContinue'
            AllowClobber = $AllowClobber
            }
    
        if ($CommandName -ne $null) { $params.Add('CommandName', $CommandName) }
    
        Import-Module (Import-PSSession @params) -Scope Global -WarningAction SilentlyContinue
    }
    
function Connect-QTMsolService
{
        [CmdletBinding()]
        Param([switch] $UseMfa, [PSCredential] $Credential = ([PSCredential]::Empty))
    
        if ($UseMfa -or $Script:ModuleManifestConfigurationData['UseMfaByDefault'])
        {
            Connect-MsolService -ErrorAction Stop
        }
        else
        {
            if ($Credential -eq ([PSCredential]::Empty))
            {
                $Credential = Get-Credential -Message "Enter your credentials to connect to Office 365"
            }
    
            Connect-MsolService -Credential $Credential -ErrorAction Stop
        }
    }
    
function Add-QTAzureRmAccount
{
        [CmdletBinding()]
        Param(
            [Parameter(
                Mandatory = $false,
                Position = 0)]
            $Subscription = ([string]::Empty),
    
            [Parameter(
                Mandatory = $false,
                Position = 1)]
            [PSCredential] $Credential = ([PSCredential]::Empty),
    
            [switch] $UseMfa
            )
    
        $params = @{
            ErrorAction = 'Stop'
            }
    
        if (!$UseMfa -and !($Script:ModuleManifestConfigurationData['UseMfaByDefault']))
        {
            if ($Credential -eq ([PSCredential]::Empty))
            {
                $Credential = Get-Credential -Message "Enter your credentials to connect to Azure RM"
            }   
    
            $params.Add('Credential', $Credential)
        }
    
        if (![string]::IsNullOrWhiteSpace($Subscription))
        {
            $params.Add('Subscription', $Subscription)
        }
    
        Add-AzureRmAccount @params
    }
    
New-Alias -Name Login-QTAzureRmAccount -Value Add-QTAzureRmAccount
    
    
    # Module import script begin
    
[System.Collections.Hashtable] $Script:ModuleManifestConfigurationData = Get-ModuleManifestPrivateData -ErrorAction Stop
    
$sessionConfigurationStoreTestResults = Test-SessionConfigurationStore -SessionConfigurationStore $Script:ModuleManifestConfigurationData

if (!$sessionConfigurationStoreTestResults.Passed)
{
    Write-Error -Message $sessionConfigurationStoreTestResults.ErrorMessage -RecommendedAction $sessionConfigurationStoreTestResults.RecommendedAction -ErrorAction Stop
}
    
Export-ConnectionManagerModuleMember