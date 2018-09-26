# Script variables

Write-Verbose -Message "Creating base script variables."

class CWSessionConfigurationData
{
    [System.Collections.IDictionary] $AuthorizationHeaderDictionary
    [PSObject] $AuthorizationResponse
    [DateTime] $TokenExpirationTime
    [bool] $Connected
    [string] $CherwellServerUrl
    [string] $CherwellApiKey
}

[CWSessionConfigurationData] $Script:CWSessionConfigurationData = [CWSessionConfigurationData]::new()

#TODO: Have to finish replacing script variables with configuration structure.

Write-Verbose -Message "Adding helper functions."
# Non-exported helper functions

function Set-CWSessionVariables
{
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true)]
        [string] $CherwellServerUrl,

        [Parameter(
            Mandatory = $true)]
        [string] $CherwellApiKey,

        [Parameter(
            Mandatory = $true)]
        [PSObject] $AuthorizationResponse
        )

    Write-Verbose -Message "Setting CherwellServerUrl"

    $Script:CWSessionConfigurationData.CherwellServerUrl = $CherwellServerUrl 

    Write-Verbose -Message "CherwellServerUrl set to $Script:CWSessionConfigurationData.CherwellServerUrl"

    Write-Verbose -Message "Setting CherwellApiKey"

    $Script:CWSessionConfigurationData.CherwellApiKey = $CherwellApiKey

    Write-Verbose -Message "CherwellApiKey set to $Script:CWSessionConfigurationData.CherwellApiKey"

    Write-Verbose -Message "Setting Authorization Response"

    $Script:CWSessionConfigurationData.AuthorizationResponse = $AuthorizationResponse

    $Script:CWSessionConfigurationData.AuthorizationHeaderDictionary = @{'Authorization' = "bearer $($AuthorizationResponse.access_token)"}

    $Script:CWSessionConfigurationData.TokenExpirationTime = [DateTime]$Script:CWSessionConfigurationData.AuthorizationResponse.'.expires'

    $Script:CWSessionConfigurationData.Connected = $true
}

function Set-CWSessionConfigurationData
{
    Param(
        [Parameter(
            Mandatory = $true)]
        [string] $CherwellServerUrl,

        [Parameter(
            Mandatory = $true)]
        [string] $CherwellApiKey,

        [Parameter(
            Mandatory = $true)]
        [PSObject] $AuthorizationResponse
        )



    $Script:CWSessionConfigurationData.CherwellServerUrl = $CherwellServerUrl

    $Script:CWSessionConfigurationData.CherwellApiKey = $CherwellApiKey

    $Script:CWSessionConfigurationData.AuthorizationResponse = $AuthorizationResponse

    $Script:CWSessionConfigurationData.AuthorizationHeaderDictionary = @{'Authorization' = "bearer $($AuthorizationResponse.access_token)"}

    $Script:CWSessionConfigurationData.TokenExpirationTime = $AuthorizationResponse.'.expires'

    $Script:CWSessionConfigurationData.Connected = $true
}

function Test-CWSessionConnected
{
    if ($null -eq $Script:CWSessionConfigurationData.TokenExpirationTime)
    {
        return $false
    }

    $dateNow = Get-Date

    if ($dateNow -gt $Script:CWSessionConfigurationData.TokenExpirationTime)
    {
        return $false
    }

    return $true
}

function Get-CWFormattedUrl
{
    <#
        .SYNOPSIS
        Format the url to use in the Invoke-CWRestMethod function.

        .PARAMETER CherwellServerUrl
        Provide something other than null or white space to override the $Script:CWSessionConfigurationData.CherwellServerUrl variable in the call. If both are blank, an ArgumentNullException will be thrown.

        .PARAMETER EndPoint
        The EndPoint to connect to. Mandatory parameter, as calls to the base url should not be made.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $CherwellServerUrl,

        [Parameter(
            Mandatory = $true)]
        [string] $EndPoint
        )

    if ([string]::IsNullOrWhiteSpace($CherwellServerUrl))
    {
        $CherwellServerUrl = $Script:CWSessionConfigurationData.CherwellServerUrl

        if ([string]::IsNullOrWhiteSpace($CherwellServerUrl))
        {
            throw "No Cherwell Server Url provided."
        }
    }

    return "$($CherwellServerUrl.TrimEnd('/'))/$($EndPoint.TrimStart('/'))"
}

function Get-CWServerAuthorizationHeaderDictionary
{
    <#
        .SYNOPSIS
        Get and validate the IDictionary to use as an authorization header in the request.

        .PARAMETER AuthorizationHeaderDictionary
        Provide something other than null to override the $Script:CWSessionConfigurationData.AuthorizationHeaderDictionary variable. If both are null, an ArgumentNullException will be thrown.
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $false)]
        [AllowNull()]
        [System.Collections.IDictionary] $AuthorizationHeaderDictionary = $null,

        [Parameter(
            Mandatory = $false)]
        [PSCredential] $WebCredential = ([PSCredential]::Empty),

        [switch] $UseDefaultCredentials
        )

    if ($null -eq $AuthorizationHeaderDictionary)
    {
        $AuthorizationHeaderDictionary = $Script:CWSessionConfigurationData.AuthorizationHeaderDictionary

        if ($null -eq $AuthorizationHeaderDictionary)
        {
            throw "No Cherwell authorization header provided. Either supply one with the -AuthorizationHeaderDictionary parameter of the Connect-CWService function, or supply one with the function you're calling."
        }
    }

    if ($AuthorizationHeaderDictionary['Authorization'] -notmatch 'bearer') 
    { 
        throw "Authorization header with bearer token not formatted properly."; 
    }

    if ($Script:CWSessionConfigurationData.Connected)
    {
        if (!(Test-CWSessionConnected))
        {
            try
            {
                Connect-CWService -CherwellServerUrl $Script:CWSessionConfigurationData.CherwellServerUrl -CherwellApiKey $Script:CWSessionConfigurationData.CherwellApiKey -WebCredential $WebCredential -UseDefaultCredentials:$UseDefaultCredentials -Reconnect -ErrorAction Stop
            }
            catch
            {
                throw "Your authorization token is expired, and it was not able to be refreshed - $($_)"   
            }
        }
    }

    return $AuthorizationHeaderDictionary
}

function Get-CWPrivateData
{
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [string] $Key
        )

    try
    {
        [string] $value = $MyInvocation.MyCommand.Module.PrivateData[$Key]

        if (![string]::IsNullOrWhiteSpace($value))
        {
            return $value
        }
    }
    catch
    {
        throw "PrivateData improperly formatted"
    }
}

function Write-CWError
{
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true)]
        $ThrownError,

        [Parameter(
            Mandatory = $false)]
        [AllowNull()]
        [AllowWhiteSpace()]
        [string] $Message,

        [Parameter(
            Mandatory = $false)]
        [string] $Category = "NotSpecified",

        [Parameter(
            Mandatory = $false)]
        [string] $RecommendedAction = "None Specified"
        )

    $params = @{
        Message = $Message
        Category = $Category
        RecommendedAction = $RecommendedAction
        }

    $typeName = $ThrownError.GetType().Name

    if ($typeName -eq 'ErrorRecord') 
    { 
        $params.Add('Exception',$ExceptionOrErrorRecord.Exception) 
    }
    elseif ($typeName -match 'Exception')
    { 
        $params.Add('Exception',$ExceptionOrErrorRecord) 
    }

    Write-Error @params
}

function Invoke-CWRestMethod
{
    <#
        .SYNOPSIS
        Internal function for calling the Cherwell Rest Api methods.

        .DESCRIPTION
        Internal function used to make the Invoke-RestMethod calls to the Cherwell Rest Api. Handles Server url validation and authorization.

        Make this call instead of Invoke-RestMethod when creating new cmdlets for this module.

        .PARAMETER EndPoint
        Endpoint on the Cherwell Rest Api to call.

        .PARAMETER Method
        The method to use when making the Invoke-RestMthod calls to the Cherwell Rest Api.

        .PARAMETER Body
        The body to send with the HTTP request. Defaults to $null, and the -Body parameter will not be used on Invoke-RestMethod.

        .PARAMETER ContentType
        The content type to use for the HTTP request. Defaults to $null, and the -ContentType parameter will not be used on Invoke-RestMethod.

        .PARAMETER AuthorizationHeaderDictionary
        The a dictionary to use as the authorization header in the Invoke-RestMethod cmdlet. Only needed if there is no Private Data key named 'CherwellApiKey' and no session has been created by running Connect-CWService with the -CherwellApiKey parameter.

        .PARAMETER WebCredential
        The WebCredential to use when making the web request. Do not use with -UseDefaultCredentials switch.

        .PARAMETER UseDefaultCredentials
        Use the sessions default credentials to make the web request. Do not use if you provide web credentials with -WebCredential.

        .PARAMETER NoAuthorizationHeader
        Run the command with no authorization header. Will provoke and Access Denied message unless using to generate the initial access token.
        
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [string] $EndPoint, 

        [Parameter(
            Mandatory = $false,
            Position = 1)]
        [ValidateSet("Post","Put","Get","Delete")]
        [string] $Method = "Get", 

        [Parameter(
            Mandatory = $false,
            Position = 2)]
        [AllowNull()]
        [object] $Body = $null, 

        [Parameter(
            Mandatory = $false,
            Position = 3)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $ContentType = $null, 

        [Parameter(
            Mandatory = $false,
            Position = 4)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $CherwellServerUrl = $null,

        [Parameter(
            Mandatory = $false,
            Position = 5)]
        [AllowNull()]
        [System.Collections.IDictionary] $AuthorizationHeaderDictionary = $null, 

        [Parameter(
            Mandatory = $false,
            Position = 6)]
        [PSCredential] $WebCredential = ([PSCredential]::Empty),

        [switch] $UseDefaultCredentials,
        [switch] $NoAuthorizationHeader
        )

        # Tried using parameter sets for this base value, but the got out of control quickly on functions the call this cmdlet.

        # Easier to allow all, then check everything in the base function.

    if ($UseDefaultCredentials -and ($WebCredential -ne [PSCredential]::Empty))
    {
        $errMessage = "`$UseDefaultCredentials cannot be used if `$Credential is supplied."
        Write-CWError -ThrownError (New-Object -TypeName System.Exception -ArgumentList $errMessage) -Message $errMessage -Category InvalidArgument -RecommendedAction "Use -UseDefaultCredential, -Credential, or neither." -ErrorAction Stop
    }

    $uri = Get-CWFormattedUrl -CherwellServerUrl $CherwellServerUrl -EndPoint $EndPoint -ErrorAction Stop

    Write-Verbose -Message "Connecting to endpoint $uri"

    $params = @{
        Uri = $uri
        Method = $Method
        ErrorAction = "Stop"
        UseBasicParsing = $true
        }

    if (!$NoAuthorizationHeader)
    {
        $ValidatedAuthorizationHeaderDictionary = Get-CWServerAuthorizationHeaderDictionary -AuthorizationHeaderDictionary $AuthorizationHeaderDictionary -WebCredential $WebCredential -UseDefaultCredentials:$UseDefaultCredentials -ErrorAction Stop

        Write-Verbose -Message "Authorization found"

        $params.Add('Headers', $ValidatedAuthorizationHeaderDictionary)
    }
    else
    {
        Write-Verbose -Message "Running with no authorization"
    }

    if ($UseDefaultCredentials)
    {
        Write-Verbose -Message "Connecting to web with default credentials"
        $params.Add('UseDefaultCredentials', $true) 
    }
    elseif ($WebCredential -ne [PSCredential]::Empty)
    {
        Write-Verbose -Message "Connecting to web as $($WebCredential.UserName)"
        $params.Add('Credential', $WebCredential)
    }
    else
    {
        Write-Verbose -Message "Connecting to web anonymously"
    }

    if ($Body -ne $null)
    {
        Write-Verbose -Message "Adding content body"
        $params.Add('Body', $Body)

        if (![string]::IsNullOrWhiteSpace($ContentType))
        {
            Write-Verbose -Message "Adding content type $ContentType"
            $params.Add('ContentType', $ContentType)
        }
    }
 
    Invoke-RestMethod @params
}

Write-Verbose -Message "Adding exportable functions."

# Exported functions

    # Connection functions

function Get-CWAuthorization
{
    <#
        .SYNOPSIS
        Get an authorization response for the Cherwell Api

        .DESCRIPTION
        Get an authorization response from the Cherwell server. Returned as a PS object deserialized from JSON

        .PARAMETER CherwellCredential
        The Cherwell account WebCredential to use to authenticate

        .PARAMETER CherwellServerUrl
        The url of the Cherwell Api. This can be supplied as a parameter to this function, or stored in the CherwellApiTools module manifest under the PrivateData section. Create a key called 'CherwellServerUrl' and set it to the url.

        .PARAMETER CherwellApiKey
        The api key to authorize connection. This can be supplied as a parameter to this function, or stored in the CherwellApiTools module manifest under the PrivateData section. Create a key called 'CherwellApiKey' and set it to the url.

        .PARAMETER WebCredential
        The WebCredential to use when making the web request. Do not use with -UseDefaultCredentials switch.

        .PARAMETER UseDefaultCredentials
        Use the sessions default credentials to make the web request. Do not use if you provide web credentials with -WebCredential.
    #>

    [CmdletBinding(DefaultParameterSetName = "INITIALWINDOWS")]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "INITIALINTERNAL")]
        [PSCredential] $CherwellCredential,

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "RECONNECTINTERNAL")]
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "RECONNECTWINDOWS")]
        [string] $RefreshToken,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "INITIALINTERNAL")]
        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "RECONNECTINTERNAL")]
        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "RECONNECTWINDOWS")]
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ParameterSetName = "INITIALWINDOWS")]
        [string] $CherwellServerUrl = $null,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "INITIALINTERNAL")]
        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "RECONNECTINTERNAL")]
        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "RECONNECTWINDOWS")]
        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "INITIALWINDOWS")]
        [string] $CherwellApiKey = $null,        
        
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "INITIALINTERNAL")]
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "RECONNECTINTERNAL")]
        [PSCredential] $WebCredential = ([PSCredential]::Empty),

        [Parameter(
            Mandatory = $false,
            ParameterSetName = "INITIALINTERNAL")]        
        [Parameter(
            Mandatory = $false,
            ParameterSetName = "RECONNECTINTERNAL")]
        [switch] $UseDefaultCredentials
        )

    if (($PSCmdlet.ParameterSetName -like "*WINDOWS") -and !$UseDefaultCredentials)
    {
        $UseDefaultCredentials = $true
    }

    if ([string]::IsNullOrWhiteSpace($CherwellServerUrl))
    {
        $CherwellServerUrl = $MyInvocation.MyCommand.Module.PrivateData['CherwellApiKey']

        if ([string]::IsNullOrWhiteSpace($CherwellServerUrl))
        {
            throw "No Cherwell Api Key provided. Either supply one with the -CherwellServerUrl parameter, or create a private data key called 'CherwellServerUrl' in the module manifest with the url."   
        }
    }

    if ([string]::IsNullOrWhiteSpace($CherwellApiKey))
    {
        $CherwellApiKey = $MyInvocation.MyCommand.Module.PrivateData['CherwellApiKey']

        if ([string]::IsNullOrWhiteSpace($CherwellApiKey))
        {
            throw "No Cherwell Api Key provided. Either supply one with the -CherwellApiKey parameter, or create a private data key called 'CherwellApiKey' in the module manifest with the url."     
        }
    }

    $endPoint = "token"

    if ($PSCmdlet.ParameterSetName -like "*INTERNAL")
    {
        $authMode = "Internal"
    }
    else
    {
        $authMode = "Windows"
    }

    $tokenRequestBody = @{
        "Accept" = "application/json"
        "client_id" = $CherwellApiKey
        }


    if ($PSCmdlet.ParameterSetName -like "RECONNECT*")
    {
        $tokenRequestBody.Add('refresh_token', $RefreshToken)
        $tokenRequestBody.Add('grant_type', 'refresh_token')
    }
    else
    {
        if ($PSCmdlet.ParameterSetName -eq "INITIALINTERNAL")
        {
            $tokenRequestBody.Add('username', $CherwellCredential.UserName)
            $tokenRequestBody.Add('password', $CherwellCredential.GetNetworkCredential().Password)
        }
        
        $tokenRequestBody.Add('grant_type', 'password')
    }

    $endPoint = "$($endPoint)?auth_mode=$authMode&api_key=$CherwellApiKey"

    Invoke-CWRestMethod -EndPoint $endPoint -Method Post -Body $tokenRequestBody -CherwellServerUrl $CherwellServerUrl -WebCredential $WebCredential -UseDefaultCredentials:$UseDefaultCredentials -NoAuthorizationHeader -ErrorAction Stop
}

function Connect-CWService
{
    <#
        .SYNOPSIS
        Create a session with the Cherwell Api service.

        .DESCRIPTION
        Stores your authentication header, server url, and api key as script variables to simulate a stateful connection to the server.
        All actions happen via a stateless Invoke-RestMethod command, however, and no real session is maintained on the server.

        .PARAMETER CherwellCredential
        The Cherwell account credentials to use to authenticate

        .PARAMETER CherwellServerUrl
        The url of the Cherwell Api. This can be supplied as a parameter to this function, or stored in the CherwellApiTools module manifest under the PrivateData section. Create a key called 'CherwellServerUrl' and set it to the url.

        .PARAMETER CherwellApiKey
        The api key to authorize connection. This can be supplied as a parameter to this function, or stored in the CherwellApiTools module manifest under the PrivateData section. Create a key called 'CherwellApiKey' and set it to the url.

        .PARAMETER WebCredential
        The WebCredential to use when making the web request. Do not use with -UseDefaultCredentials switch.

        .PARAMETER UseDefaultCredentials
        Use the sessions default credentials to make the web request. Do not use if you provide web credentials with -WebCredential.
    #>

    [CmdletBinding(DefaultParameterSetName = "INITIALWINDOWS")]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "INITIALINTERNAL")]
        [PSCredential] $CherwellCredential,

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "RECONNECTINTERNAL")]
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "RECONNECTWINDOWS")]
        [string] $RefreshToken,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "INITIALINTERNAL")]
        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "RECONNECTINTERNAL")]
        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "RECONNECTWINDOWS")]
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ParameterSetName = "INITIALWINDOWS")]
        [string] $CherwellServerUrl = $null,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "INITIALINTERNAL")]
        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "RECONNECTINTERNAL")]
        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "RECONNECTWINDOWS")]
        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "INITIALWINDOWS")]
        [string] $CherwellApiKey = $null,        
        
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "INITIALINTERNAL")]
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "RECONNECTINTERNAL")]
        [PSCredential] $WebCredential = ([PSCredential]::Empty),
        
        [Parameter(
            Mandatory = $false,
            ParameterSetName = "INITIALINTERNAL")]        
        [Parameter(
            Mandatory = $false,
            ParameterSetName = "RECONNECTINTERNAL")]
        [switch] $UseDefaultCredentials,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = "RECONNECTINTERNAL")]
        [Parameter(
            Mandatory = $true,
            ParameterSetName = "RECONNECTWINDOWS")]
        [switch] $Reconnect
        )

    if ([string]::IsNullOrWhiteSpace($CherwellServerUrl))
    {
        $CherwellServerUrl = Get-CWPrivateData -Key 'CherwellServerUrl' -ErrorAction Stop
    }

    if ([string]::IsNullOrWhiteSpace($CherwellApiKey))
    {
        $CherwellApiKey = Get-CWPrivateData -Key 'CherwellApiKey' -ErrorAction Stop
    }

    Write-Verbose -Message "Connecting to $CherwellServerUrl"

    $cwAuthorizationParams = @{
        CherwellServerUrl = $CherwellServerUrl
        CherwellApiKey = $CherwellApiKey
        ErrorAction = "Stop"
        }

    if ($Reconnect)
    {
        $cwAuthorizationParams.Add('RefreshToken', $Script:CWSessionConfigurationData.AuthorizationResponse.refresh_token)
    }
    
    if ($PSCmdlet.ParameterSetName -eq "INITIALINTERNAL")
    {
        $cwAuthorizationParams.Add('CherwellCredential', $CherwellCredential)
    }

    if ($WebCredential -ne ([PSCredential]::Empty))
    {
        $cwAuthorizationParams.Add('WebCredential', $WebCredential)
    }

    if ($PSCmdlet.ParameterSetName -notlike "*WINDOWS")
    {
        $cwAuthorizationParams.Add('UseDefaultCredentials', $UseDefaultCredentials)
    }

    try
    {
        $authResponse = Get-CWAuthorization @cwAuthorizationParams
    }
    catch
    {
        if ($Script:Connected) 
        { 
            $Script:CWSessionConfigurationData.Connected = $false 
        }

        throw
    }

    Set-CWSessionVariables -CherwellServerUrl $CherwellServerUrl -CherwellApiKey $CherwellApiKey -AuthorizationResponse $authResponse -ErrorAction Stop
}

function Disconnect-CWService
{
    [CmdletBinding()]
    Param()
    [System.Collections.IDictionary] $Script:CWSessionConfigurationData.AuthorizationHeaderDictionary = @{}
    [PSObject] $Script:CWSessionConfigurationData.AuthorizationResponse = $null
    [DateTime] $Script:CWSessionConfigurationData.TokenExpirationTime = (Get-Date).AddMinutes(-1)
    [bool] $Script:CWSessionConfigurationData.Connected = $false
    [string] $Script:CWSessionConfigurationData.CherwellServerUrl = $null
    [string] $Script:CWSessionConfigurationData.CherwellApiKey = $null

    Write-Verbose -Message "Session data cleared"
}


    # Business object functions

function Save-CWBusinessObject
{
    <#
        .SYNOPSIS
        Save a Cherwell Business Object. Used to update an existing object, or to create a new one. For a new object, leave the RecId field blank.
        
        .DESCRIPTION
        Invoke a rest method to the /api/V1/savebusinessobject endpoint to create or update a Cherwell Business Object.

        .ENDPOINT
        /api/v1/savebusinessobject

        .PARAMETER InputObject
        The Cherwell Business Object to create/update.

        .PARAMETER CherwellServerUrl
        The url of the Cherwell Api. Only needed if there is no Private Data key named 'CherwellServerUrl' and no session has been created by running Connect-CWService with the -CherwellServerUrl parameter.

        .PARAMETER AuthorizationHeaderDictionary
        The a dictionary to use as the authorization header in the Invoke-RestMethod cmdlet. Only needed if there is no Private Data key named 'CherwellApiKey' and no session has been created by running Connect-CWService with the -CherwellApiKey parameter.

        .PARAMETER WebCredential
        The WebCredential to use when making the web request. Do not use with -UseDefaultCredentials switch.

        .PARAMETER UseDefaultCredentials
        Use the sessions default credentials to make the web request. Do not use if you provide web credentials with -WebCredential.            
    #>
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true)]
        [PSObject] $InputObject,

        [Parameter(
            Mandatory = $false,
            Position = 1)]
        [string] $ContentType = "application/json",

        [Parameter(
            Mandatory = $false,
            Position = 1)]
        [string] $CherwellServerUrl = $null,

        [Parameter(
            Mandatory = $false,
            Position = 2)]
        [System.Collections.IDictionary] $AuthorizationHeaderDictionary = $null,

        [Parameter(
            Mandatory = $false,
            Position = 3)]
        [PSCredential] $WebCredential = ([PSCredential]::Empty),

        [switch] $UseDefaultCredentials
        )

    $params = @{
        EndPoint = "api/v1/savebusinessobject" 
        Method = "Post"
        Body = $InputObject
        AuthorizationHeaderDictionary = $AuthorizationHeaderDictionary
        CherwellServerUrl = $CherwellServerUrl
        WebCredential = $WebCredential
        UseDefaultCredentials = $UseDefaultCredentials
        ContentType = $ContentType
        ErrorAction = "Stop"
        }

    Invoke-CWRestMethod @params
}

function Get-CWBusinessObject
{
    <#
        .SYNOPSIS
        Get a Cherwell Business object
        
        .DESCRIPTION
        Invoke a rest method to the /api/v1/getbusinessobject/busobid/$BusinessObjectId/busobrecid/$RecId endpoint to get business object data

        .PARAMETER RecId
        The RecId of the object to retrieve

        .PARAMETER BusinessObjectId
        The Business Object Type Id of the object to retrieve

        .PARAMETER CherwellServerUrl
        The url of the Cherwell Api. Only needed if there is no Private Data key named 'CherwellServerUrl' and no session has been created by running Connect-CWService with the -CherwellServerUrl parameter.

        .PARAMETER AuthorizationHeaderDictionary
        The a dictionary to use as the authorization header in the Invoke-RestMethod cmdlet. Only needed if there is no Private Data key named 'CherwellApiKey' and no session has been created by running Connect-CWService with the -CherwellApiKey parameter.

        .PARAMETER WebCredential
        The WebCredential to use when making the web request. Do not use with -UseDefaultCredentials switch.

        .PARAMETER UseDefaultCredentials
        Use the sessions default credentials to make the web request. Do not use if you provide web credentials with -WebCredential.
    #>


    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "RECID")]
        [string] $RecId,

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "PUBID")]
        [string] $PublicId,

        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = "RECID")]
        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = "PUBID")]
        [string] $BusinessObjectId,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "RECID")]
        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "PUBID")]
        [string] $CherwellServerUrl = $null,

        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "RECID")]
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "PUBID")]
        [System.Collections.IDictionary]  $AuthorizationHeaderDictionary = $null,

        [Parameter(
            Mandatory = $false,
            Position = 4,
            ParameterSetName = "RECID")]
        [Parameter(
            Mandatory = $false,
            Position = 4,
            ParameterSetName = "PUBID")]
        [PSCredential] $WebCredential = ([PSCredential]::Empty),

        [switch] $UseDefaultCredentials
        )

    if ($PSCmdlet.ParameterSetName -eq "RECID")
    {
        $endPoint = "api/v1/getbusinessobject/busobid/$BusinessObjectId/busobrecid/$RecId"
    }
    else
    {
        $endPoint = "api/v1/getbusinessobject/busobid/$BusinessObjectId/publicid/$PublicId"
    }

    $params = @{
        EndPoint = $endPoint
        Method = "Get"
        AuthorizationHeaderDictionary = $AuthorizationHeaderDictionary
        CherwellServerUrl = $CherwellServerUrl
        WebCredential = $WebCredential 
        UseDefaultCredentials = $UseDefaultCredentials 
        }

    Invoke-CWRestMethod @params
}

function Get-CWRelatedBusinessObject
{
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [string] $ParentRecId,

        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [string] $ParentBusinessObjectId,

        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [string] $RelationshipId,

        [Parameter(
            Mandatory = $false,
            Position = 3)]
        [string] $CherwellServerUrl = $null,

        [Parameter(
            Mandatory = $false,
            Position = 4)]
        [System.Collections.IDictionary]  $AuthorizationHeaderDictionary = $null,

        [Parameter(
            Mandatory = $false,
            Position = 5)]
        [PSCredential] $WebCredential = ([PSCredential]::Empty),

        [switch] $UseDefaultCredentials
        )

    $params = @{
        EndPoint = "api/V1/getrelatedbusinessobject/parentbusobid/$ParentBusinessObjectId/parentbusobrecid/$ParentRecId/relationshipid/$RelationshipId"
        Method = "Get"
        AuthorizationHeaderDictionary = $AuthorizationHeaderDictionary
        CherwellServerUrl = $CherwellServerUrl
        WebCredential = $WebCredential 
        UseDefaultCredentials = $UseDefaultCredentials 
        }

    Invoke-CWRestMethod @params
}

function Get-CWBusinessObjectTemplate
{
    <#
        .SYNOPSIS
        Get a Cherwell Business object template to populate with data for saving.
        
        .DESCRIPTION
        Invoke a rest method to the /api/V1/getbusinessobjecttemplate endpoint with a POST request to get business object data.

        .PARAMETER BusinessObjectId
        The Business Object Type Id of the template to retrieve.

        .PARAMETER FieldNames
        The names of the fields to request with the template response.

        .PARAMETER CherwellServerUrl
        The url of the Cherwell Api. Only needed if there is no Private Data key named 'CherwellServerUrl' and no session has been created by running Connect-CWService with the -CherwellServerUrl parameter.

        .PARAMETER AuthorizationHeaderDictionary
        The a dictionary to use as the authorization header in the Invoke-RestMethod cmdlet. Only needed if there is no Private Data key named 'CherwellApiKey' and no session has been created by running Connect-CWService with the -CherwellApiKey parameter.

        .PARAMETER IncludeAll
        Include all fields of the Cherwell Business Object in the returned template.

        .PARAMETER IncludeRequired
        Include all/only required fields of the Cherwell Business Object in the returned template.

        .PARAMETER WebCredential
        The WebCredential to use when making the web request. Do not use with -UseDefaultCredentials switch.

        .PARAMETER UseDefaultCredentials
        Use the sessions default credentials to make the web request. Do not use if you provide web credentials with -WebCredential.
    #>

    [CmdletBinding(DefaultParameterSetName = "FIELDNAMES")]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "INCLUDEALL")]
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "INCLUDEREQUIRED")]
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "FIELDNAMES")]
        [string] $BusinessObjectId,


        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = "FIELDNAMES")]
        [string[]] $FieldNames,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "INCLUDEALL")]
        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "INCLUDEREQUIRED")]
        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "FIELDNAMES")]
        [string] $CherwellServerUrl = $null,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "INCLUDEALL")]
        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "INCLUDEREQUIRED")]
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "FIELDNAMES")]
        [System.Collections.IDictionary]  $AuthorizationHeaderDictionary = $null,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = "INCLUDEALL")]
        [switch] $IncludeAll,

        [Parameter(
            Mandatory = $true,
            ParameterSetName = "INCLUDEREQUIRED")]
        [switch] $IncludeRequired,

        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "INCLUDEALL")]
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "INCLUDEREQUIRED")]
        [Parameter(
            Mandatory = $false,
            Position = 4,
            ParameterSetName = "FIELDNAMES")]
        [PSCredential] $WebCredential = ([PSCredential]::Empty),

        [switch] $UseDefaultCredentials
        )

    $params = @{
        busObId = $BusinessObjectId
        }

    if ($IncludeAll) 
    { 
        $params.Add('includeAll', $true) 
    }
    elseif ($IncludeRequired) 
    { 
        $params.Add('includeRequired', $true) 
    }
    else 
    { 
        $params.Add('fieldIds', $FieldNames) 
    }

    Invoke-CWRestMethod -EndPoint "api/V1/getbusinessobjecttemplate" -Method Post -Body ($params | ConvertTo-Json) -AuthorizationHeaderDictionary $AuthorizationHeaderDictionary -CherwellServerUrl $CherwellServerUrl -WebCredential $WebCredential -UseDefaultCredentials:$UseDefaultCredentials -ContentType "application/json" -ErrorAction Stop

}

function Set-CWBusinessObjectField
{
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0)]
        [ref] $BusinessObject,

        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [string] $FieldName,

        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [object] $NewValue
        )

    $field = $BusinessObject.Value.fields | Where-Object -Property Name -EQ $FieldName

    if ($null -eq $field)
    {
        Write-Error -Message "No field found matching $FieldName" -Exception (New-Object -TypeName System.NullReferenceException) -Category InvalidArgument -ErrorAction Stop
    }

    ($BusinessObject.Value.fields | Where-Object -Property Name -EQ $FieldName).value = $NewValue
    ($BusinessObject.Value.fields | Where-Object -Property Name -EQ $FieldName).dirty = $true
}

function New-CWBusinessObjectBatchDeletionObject
{
    Param(
        [Parameter(
            Mandatory = $false,
            Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $BusinessObjectId,

        [Parameter(
            Mandatory = $false,
            Position = 1)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $BusinessObjectPublicId,

        [Parameter(
            Mandatory = $false,
            Position = 2)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $RecId
        )

    [PSCustomObject]@{
        busObId = $BusinessObjectId
        busObPublicId = $BusinessObjectPublicId
        busObRecId = $RecId
        }
}

function Remove-CWBusinessObjectBatch
{
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true)]
        [PSObject[]] $BusinessObjectBatchDeletionObjects,

        [Parameter(
            Mandatory = $false,
            Position = 1)]
        [string] $CherwellServerUrl = $null,

        [Parameter(
            Mandatory = $false,
            Position = 2)]
        [System.Collections.IDictionary] $AuthorizationHeaderDictionary = $null,

        [Parameter(
            Mandatory = $false,
            Position = 3)]
        [PSCredential] $WebCredential = ([PSCredential]::Empty),

        [switch] $UseDefaultCredentials,

        [switch] $StopOnError
        )

    Invoke-CWRestMethod -EndPoint "api/v1/deletebusinessobjectbatch" -Method Post -Body ([PSCustomObject]@{deleteRequests = $BusinessObjectBatchDeletionObjects; stopOnError = $StopOnError}) -ContentType "application/json" -CherwellServerUrl $CherwellServerUrl -AuthorizationHeaderDictionary $AuthorizationHeaderDictionary -WebCredential $WebCredential -UseDefaultCredentials:$UseDefaultCredentials -ErrorAction Stop
}

function Remove-CWBusinessObject
{
    [CmdletBinding(DefaultParameterSetName = "BATCH")]
    Param(

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "RELATIONSHIP")]
        [string] $ParentRecId,

        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = "RELATIONSHIP")]
        [string] $ParentBusinessObjectId,
        [Parameter(
            Mandatory = $true,
            Position = 2,
            ParameterSetName = "RELATIONSHIP")]
        [string] $RelationshipId,

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "SINGLERECID")]
        [Parameter(
            Mandatory = $true,
            Position = 3,
            ParameterSetName = "RELATIONSHIP")]
        [string] $RecId,

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "SINGLEPUBID")]
        [string] $PublicId,

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = "BATCH",
            ValueFromPipeline = $true)]
        [PSObject[]] $BusinessObjectBatchDeletionObjects,

        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = "SINGLERECID")]
        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = "SINGLEPUBID")]
        [string] $BusinessObjectId,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "SINGLERECID")]
        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "SINGLEPUBID")]
        [Parameter(
            Mandatory = $false,
            Position = 4,
            ParameterSetName = "RELATIONSHIP")]
        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = "BATCH")]
        [string] $CherwellServerUrl = $null,

        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "SINGLERECID")]
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "SINGLEPUBID")]
        [Parameter(
            Mandatory = $false,
            Position = 5,
            ParameterSetName = "RELATIONSHIP")]
        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = "BATCH")]
        [System.Collections.IDictionary]  $AuthorizationHeaderDictionary = $null,

        [Parameter(
            Mandatory = $false,
            Position = 4,
            ParameterSetName = "SINGLERECID")]
        [Parameter(
            Mandatory = $false,
            Position = 4,
            ParameterSetName = "SINGLEPUBID")]
        [Parameter(
            Mandatory = $false,
            Position = 6,
            ParameterSetName = "RELATIONSHIP")]
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = "BATCH")]
        [PSCredential] $WebCredential = ([PSCredential]::Empty),

        [Parameter(
            Mandatory = $false,
            ParameterSetName = "BATCH")]
        [switch] $StopOnError,

        [switch] $UseDefaultCredentials
        )

    $params = @{
        CherwellServerUrl = $CherwellServerUrl
        AuthorizationHeaderDictionary = $AuthorizationHeaderDictionary
        WebCredential = $WebCredential
        UseDefaultCredentials = $UseDefaultCredentials
        ErrorAction = "Stop"
        }

    if ($PSCmdlet.ParameterSetName -eq "SINGLEPUBID")
    {
        $params.Add('EndPoint', "api/V1/deletebusinessobject/busobid/$BusinessObjectId/publicid/$PublicId")
        $params.Add('Method', 'Delete')
    }
    elseif ($PSCmdlet.ParameterSetName -eq "SINGLERECID")
    {
        $params.Add('EndPoint', "api/V1/deletebusinessobject/busobid/$BusinessObjectId/busobrecid/$RecId")
        $params.Add('Method', 'Delete')        
    }
    elseif ($PSCmdlet.ParameterSetName -eq "BATCH")
    {
        $params.Add('EndPoint', "api/v1/deletebusinessobjectbatch")
        $params.Add('Method', "Post")
        $params.Add('Body', ([PSCustomObject]@{deleteRequests = $BusinessObjectBatchDeletionObjects; stopOnError = $StopOnError}))
    }
    elseif ($PSCmdlet.ParameterSetName -eq "RELATIONSHIP")
    {
        $params = @{
            EndPoint = "api/V1/deleterelatedbusinessobject/parentbusobid/$ParentBusinessObjectId/parentbusobrecid/$ParentRecId/relationshipid/$RelationshipId/busobrecid/$RecId"
            Method = 'Delete'
            }
    }
    else
    {
        Write-Error -Exception (New-Object -TypeName System.NotImplementedException -ArgumentList "$($PSCmdlet.ParameterSetName) parameter set not implemented.") -Message "$($PSCmdlet.ParameterSetName) parameter set not implemented." -ErrorAction Stop
    }

    Invoke-CWRestMethod @params
}


# Function aliases

New-Alias -Value Get-CWAuthorization -Name New-CWAuthorizationResponse
New-Alias -Value Connect-CWService -Name Login-CWService
New-Alias -Value Disconnect-CWService -Name Logout-CWService
New-Alias -Value Save-CWBusinessObject -Name Set-CWBusinessObject
New-Alias -Value Set-CWBusinessObjectField -Name Update-CWBusinessObjectField
New-Alias -Value Get-CWBusinessObjectTemplate -Name New-CWBusinessObjectTemplate

$functions = 'Get-CWAuthorization','Connect-CWService','Disconnect-CWService','Save-CWBusinessObject','Get-CWBusinessObject','Get-CWRelatedBusinessObject','Set-CWBusinessObjectField','Get-CWBusinessObjectTemplate', 'New-CWOffboardRequest'

$aliases = 'Login-CWService','Update-CWBusinessObjectField','Set-CWBusinessObject','Logout-CWService','New-CWAuthorizationResponse','New-CWBusinessObjectTemplate'

Export-ModuleMember -Function $functions -Alias $aliases