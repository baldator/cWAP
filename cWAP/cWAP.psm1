enum Ensure {
    Absent
    Present
}

enum ExternalPreauthentication {
    PassThrough
    ADFS
}

enum BackendServerAuthenticationModeValues {
    NoAuthentication
    IntegratedWindowsAuthentication
}

enum BackendServerCertificateValidationValues {
    None
    ValidateCertificate
}

enum ClientCertificateAuthenticationBindingModeValues {
    None
    ValidateCertificate
}

enum UserIdleTimeoutActionValues {
    Signout 
    Reauthenticate
}

Function Test-sslBinding {
    [CmdletBinding()]
    param(
        [String]
        $bindingName,
        [String]
        $certificateThumbprint,
        [UInt16]
        $port
    )

    $binding = $null
    $lineNum = 0
    $certificates = @()
    netsh http show sslcert | ForEach-Object {
        $lineNum ++
        
        if( -not ($_.Trim()) -and $binding )
        {
            $certificates += $binding
            $binding = $null
        }
        
        if( $_ -notmatch '^ (.*)\s+: (.*)$' )
        {
            return
        }

        $name = $matches[1].Trim()
        $value = $matches[2].Trim()

        if( $name -eq 'IP:port'  -or $name -eq 'Hostname:port' )
        {
            $binding = @{}
            $name = "IPPort"
            if( $value -notmatch '^(.*):(\d+)$' )
            {
                Write-Verbose 'Invalid IP address/port in netsh output.'
            }
            else
            {
                $binding['IPAddress'] = $matches[1]
                $binding['Port'] = $matches[2]
            }                
        }
        if( $value -eq '(null)' )
        {
            $value = $null
        }
        elseif( $value -eq 'Enabled' )
        {
            $value = $true
        }
        elseif( $value -eq 'Disabled' )
        {
            $value = $false
        }
        
        $binding[$name] = $value
    }

    $checkBinding = $false
    $certificates | ForEach-Object{
        if(($_.Port -eq $port) -and ($_.Hash -eq $certificateThumbprint) -and ($_.IPAddress -eq $bindingName)){
            $checkBinding = $true
        }
    }

    return $checkBinding
}

[DscResource()]
class cWAPWebsite {
    <#
    The Ensure property is used to determine if the Web Application Proxy website should be present or not absent.
    #>
    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    <#
    The DisplayName property is the name of the website.
    #>
    [DscProperty(Mandatory)]
    [string] $DisplayName

    <#
    The BackendServerUrl property is the internal url of the application to be published. 
    #>
    [DscProperty(key)]
    [string] $BackendServerUrl

    <#
    The ExternalCertificateThumbprint property is the thumbprint of the certificate, located in the local computer's certificate store, that will be bound to the
    website's external url. The cn of the certificate should match the ExternalUrl.
    #>
    [DscProperty(Mandatory)]
    [string] $ExternalCertificateThumbprint

    <#
    The ExternalUrl property is the external url of the application, that is the url users will access. 
    #>
    [DscProperty(Mandatory)]
    [string] $ExternalUrl

    <#
    The ExternalPreauthentication property define the website preauthentication mode. Possible values are: PassThrogh, ADFS
    #>
    [DscProperty()]
    [ExternalPreauthentication] $ExternalPreauthentication = "ADFS"
    
    <#
    The ADFSRelyingPartyName property define the ADFS relying party name of the application. It is required only if ExternalPreauthentication is ADFS
    #>
    [DscProperty()]
    [string] $ADFSRelyingPartyName

    <#
    The BackendServerAuthenticationSPN propery define the SPN of the relying party ID. It is required case of not claims aware relying party. 
    #>
    [DscProperty()]
    [string] $BackendServerAuthenticationSPN

    <#
    Specifies the authentication method that Web Application Proxy uses when it contacts the backend server. The acceptable values for this parameter are: NoAuthentication and IntegratedWindowsAuthentication.
    #>
    [DscProperty()]
    [BackendServerAuthenticationModeValues] $BackendServerAuthenticationMode = "NoAuthentication"

    <#
    Specifies whether Web Application Proxy validates the certificate that the backend server presents.
    #>
    [DscProperty()]
    [BackendServerCertificateValidationValues]$BackendServerCertificateValidation = "None"

    <#
    Specifies whether Web Application Proxy verifies whether the certificate that authenticates the federation server authenticates future requests. 
    #>
    [DscProperty()]
    [ClientCertificateAuthenticationBindingModeValues]$ClientCertificateAuthenticationBindingMode = "None"

    <#
    Indicates that this cmdlet disables the use of the HttpOnly flag when Web Application Proxy sets the access cookie. The access cookie provides single sign-on access to an application.
    #>
    [DscProperty()]
    [bool]$DisableHttpOnlyCookieProtection

    <#
    Indicates that Web Application Proxy does not translate HTTP host headers from public host headers to internal host headers when it forwards the request to the published application.
    #>
    [DscProperty()]
    [bool]$DisableTranslateUrlInRequestHeaders

    <#
    Indicates that Web Application Proxy does not translate internal host names to public host names in Content-Location, Location, and Set-Cookie response headers in redirect responses.
    #>
    [DscProperty()]
    [bool]$DisableTranslateUrlInResponseHeaders

    <#
    Indicates that this cmdlet enables HTTP redirect for Web Application Proxy.
    #>
    [DscProperty()]
    [bool]$EnableHTTPRedirect

    <#
    Indicates whether to enable sign out for Web Application Proxy.
    #>
    [DscProperty()]
    [bool]$EnableSignOut

    <#
    Specifies the length of time, in seconds, until Web Application Proxy closes incomplete HTTP transactions.
    #>
    [DscProperty()]
    [int]$InactiveTransactionsTimeoutSec

    <#
    Specifies the expiration time, in seconds, for persistent access cookies.
    #>
    [DscProperty()]
    [int]$PersistentAccessCookieExpirationTimeSec

    <#
    Indicates whether to enable sign out for Web Application Proxy.
    #>
    [DscProperty()]
    [bool]$UseOAuthAuthentication


    [cWAPWebsite] Get() {

        Write-Verbose -Message 'Starting retrieving configuration for website'

        try {
            Get-WebApplicationProxyApplication $this.DisplayName -ErrorAction Stop
        }
        catch {
            Write-Verbose -Message ('Error occurred while retrieving website configuration')
        }

        Write-Verbose -Message 'Finished retrieving configuration for website'
        return $this
    }

    [System.Boolean] Test() {
        # Assume compliance by default
        $Compliant = $true


        Write-Verbose -Message 'Testing for presence of WAP website'

        try {
            $Properties = Get-WebApplicationProxyApplication $this.DisplayName -ErrorAction Stop
        }
        catch {
            $Compliant = $false
            return $Compliant
        }
        

        if ($this.Ensure -eq 'Present') {
            Write-Verbose -Message 'Checking for configuration of WAP website.'
            if($Properties -eq $null){
                $Compliant = $false
            }
            else{
                if ($this.DisplayName -ne $Properties.Name){
                    $Compliant = $false
                }
    
                if($this.BackendServerUrl -ne $Properties.BackendServerUrl){
                    $Compliant = $false
                }
    
                if($this.ExternalCertificateThumbprint -ne $Properties.ExternalCertificateThumbprint){
                    $Compliant = $false
                }
                
                if($this.ExternalUrl -ne $Properties.ExternalUrl){
                    $Compliant = $false
                }
    
                if($this.ExternalPreauthentication -ne $Properties.ExternalPreauthentication){
                    $Compliant = $false
                }
    
                if($Properties.ExternalPreauthentication -eq "ADFS"){
                    if($this.ADFSRelyingPartyName -ne $Properties.ADFSRelyingPartyName){
                        $Compliant = $false
                    }
                }
    
                if($Properties.BackendServerAuthenticationMode -eq "IntegratedWindowsAuthentication"){
                    if($this.BackendServerAuthenticationSPN -ne $Properties.BackendServerAuthenticationSPN){
                        $Compliant = $false
                    }
                }   

                if($this.BackendServerAuthenticationMode -ne $Properties.BackendServerAuthenticationMode){
                    $Compliant = $false
                }
            
                if($this.BackendServerCertificateValidation -ne $Properties.BackendServerCertificateValidation){
                    $Compliant = $false
                }
             
                if($this.ClientCertificateAuthenticationBindingMode -ne $Properties.ClientCertificateAuthenticationBindingMode){
                    $Compliant = $false
                }
             
                if($this.DisableHttpOnlyCookieProtection -ne $Properties.DisableHttpOnlyCookieProtection){
                    $Compliant = $false
                }
                  
                if($this.DisableTranslateUrlInRequestHeaders -ne $Properties.DisableTranslateUrlInRequestHeaders){
                    $Compliant = $false
                } 
            
                if($this.DisableTranslateUrlInResponseHeaders -ne $Properties.DisableTranslateUrlInResponseHeaders){
                    $Compliant = $false
                } 
            
                if($this.EnableHTTPRedirect -ne $Properties.EnableHTTPRedirect){
                    $Compliant = $false
                } 
                
                if($this.EnableSignOut -ne $Properties.EnableSignOut){
                    $Compliant = $false
                } 
                
                if($this.InactiveTransactionsTimeoutSec -ne $Properties.InactiveTransactionsTimeoutSec){
                    $Compliant = $false
                } 
            
                if($this.PersistentAccessCookieExpirationTimeSec -ne $Properties.PersistentAccessCookieExpirationTimeSec){
                    $Compliant = $false
                } 
            
                if($this.UseOAuthAuthentication -ne $Properties.UseOAuthAuthentication){
                    $Compliant = $false
                } 

                Write-Verbose -Message "Current WAP configuration $Properties" 
            }
            
            if(!$compliant){
                Write-Verbose -Message 'WAP website does not match the desired state.'         
            }
        }

        if ($this.Ensure -eq 'Absent') {
            Write-Verbose -Message 'Checking for absence of WAP website.'
            if ($Properties) {
                Write-Verbose -Message
                $Compliant = $false
            }
        }

        if($Compliant){
            $Compliant = Test-sslBinding -bindingName $this.DisplayName -certificateThumbprint $Properties.ExternalCertificateThumbprint -port 443
        }

        if($Compliant){
            Write-Verbose -Message 'Compliance status: true'
        }
        else{
            Write-Verbose -Message 'Compliance status: false'
        }
        
        return $Compliant
    }

    [void] Set() {
        
        try {
            $WapWebsite = Get-webapplicationproxyapplication $this.DisplayName -ErrorAction stop
        }
        catch {
            $WapWebsite = $false
        }

        ### If WAP website shoud be present, then go ahead and create it.
        if ($this.Ensure -eq [Ensure]::Present) {
            $WapWebsiteInfo = @{
                Name                                        = $this.DisplayName
                ExternalUrl                                 = $this.ExternalUrl
                ExternalCertificateThumbprint               = $this.ExternalCertificateThumbprint
                BackendServerUrl                            = $this.BackendServerUrl
                ExternalPreauthentication                   = $this.ExternalPreauthentication
                EnableHTTPRedirect                          = $this.EnableHTTPRedirect
                UseOAuthAuthentication                      = $this.UseOAuthAuthentication
                BackendServerCertificateValidation          = $this.BackendServerCertificateValidation
                ClientCertificateAuthenticationBindingMode  = $this.ClientCertificateAuthenticationBindingMode
                DisableHttpOnlyCookieProtection             = $this.DisableHttpOnlyCookieProtection
                DisableTranslateUrlInRequestHeaders         = $this.DisableTranslateUrlInRequestHeaders
                DisableTranslateUrlInResponseHeaders        = $this.DisableTranslateUrlInResponseHeaders
                EnableSignOut                               = $this.EnableSignOut
                InactiveTransactionsTimeoutSec              = $this.InactiveTransactionsTimeoutSec
                PersistentAccessCookieExpirationTimeSec     = $this.PersistentAccessCookieExpirationTimeSec
            }

            $recreate = $false

            if ($this.BackendServerAuthenticationMode){
                $WapWebsiteInfo.Add('BackendServerAuthenticationMode', $this.BackendServerAuthenticationMode)
            }

            if ($this.ExternalPreauthentication -eq "ADFS") {
                if($this.ADFSRelyingPartyName){
                    $WapWebsiteInfo.Add('ADFSRelyingPartyName', $this.ADFSRelyingPartyName)
                    if($WapWebsite -and ($this.ADFSRelyingPartyName -ne $WapWebsite.ADFSRelyingPartyName)){
                        $recreate = $true
                    }
                }
            }
            elseif ($this.BackendServerAuthenticationSPN) {
                $WapWebsiteInfo.Add('BackendServerAuthenticationSPN', $this.BackendServerAuthenticationSPN)
            }

            if (!$WapWebsite) {
                Write-Verbose -Message 'Creating WAP website'
                Add-WebApplicationProxyApplication @WapWebsiteInfo
            }

            if ($WapWebsite -and !$recreate) {
                Write-Verbose -Message 'Editing WAP website'
                Set-WebApplicationProxyApplication @WapWebsiteInfo
            }
            else{
                Write-Verbose -Message 'Removing and recreating WAP website'
                Remove-WebApplicationProxyApplication -name $this.DisplayName
                Add-WebApplicationProxyApplication @WapWebsiteInfo
            }
        }

        if ($this.Ensure -eq [Ensure]::Absent) {
            if($WapWebsite){
                Remove-WebApplicationProxyApplication -name $this.DisplayName
            }
        }

        return
    }
}
#endregion


[DscResource()]
class cWAPConfiguration
{
    ### Determines whether or not the WAP Config should exist.
    [DscProperty()]
    [Ensure] $Ensure

	<#
    The FederationServiceName property is the name of the Active Directory Federation Services (ADFS) service. For example: adfs-service.contoso.com.
    #>
    [DscProperty(key)]
    [string] $FederationServiceName

	<#
    The Credential property is a PSCredential that represents the username/password of an Active Directory user account that is a member of
    the Domain Administrators security group. This account will be used to add a new proxy to Active Directory Federation Services (ADFS).
    #>
    [DscProperty(Mandatory)]
    [pscredential] $Credential

    <#
    The CertificateThumbprint property is the thumbprint of the certificate, located in the local computer's certificate store, that will be bound to the 
    Active Directory Federation Service (ADFS) farm.
    #>
    [DscProperty(Mandatory)]
    [string] $CertificateThumbprint

    <#
    Specifies the DNS name and port number of an HTTP proxy that this federation server proxy uses to obtain access to the federation service. Specify the value for this parameter in the following format: FQDN:PortNumber.
    Only configurable at installation time.
    #>
    [DscProperty()]
    [string] $ForwardProxy = ""

    <#
    Specifies the HTTPS port for the Web Application Proxy server. The default value is 443.
    Only configurable at installation time.
    #>
    [DscProperty()]
    [int] $HttpsPort = 443

    <#
    Specifies the port for the TLS client. Web Application Proxy uses this port for user certificate authentication. The default value is 49443.
    Only configurable at installation time.
    #>
    [DscProperty()]
    [int] $TlsClientPort = 49443

    <#
    Define the ADFS Token acceptance duration in seconds
    #>
    [DscProperty()]
    [int] $ADFSTokenAcceptanceDurationSec

    <#
    Define the user idle timeout in second
    #>
    [DscProperty()]
    [int] $UserIdleTimeoutSec

    <#
    Define the User idle timeout action. Accepted values are: Signout, Reauthenticate
    #>
    [DscProperty()]
    [UserIdleTimeoutActionValues] $UserIdleTimeoutAction

	[cWAPConfiguration] Get()
	{
		Write-Verbose -Message 'Starting retrieving Web Applucation Proxy configuration.'

        try {
            $cWAPConfiguration=Get-WebApplicationProxyConfiguration -ErrorAction Stop
        }
        catch {
            Write-Verbose -Message ('Error occurred while retrieving Web Application Proxy configuration')
        }

        Write-Verbose -Message 'Finished retrieving Web Applucation Proxy configuration.'
        return $this

	}

	[void] Set()
	{
        ### If WAP shoud be present, then go ahead and configure it.
        if ($this.Ensure -eq [Ensure]::Present) {
            try{
                $WapConfiguration = Get-WebApplicationProxyConfiguration -ErrorAction Stop
            }
            catch {
                $WapConfiguration = $false
            }

            if (!$WapConfiguration) {
                Write-Verbose -Message 'Configuring Web Application Proxy.'
                $WapSettings = @{
                    FederationServiceTrustCredential    = $this.Credential
                    CertificateThumbprint               = $this.CertificateThumbprint
                    FederationServiceName               = $this.FederationServiceName
                    ForwardProxy                        = $this.ForwardProxy
                    HttpsPort                           = $this.HttpsPort
                    TlsClientPort                       = $this.TlsClientPort
                }

                if($this.ForwardProxy -ne $null){
                    $WapSettings.Add('ForwardProxy', $this.ForwardProxy)
                }

                if($this.HttpsPort -ne $null){
                    $WapSettings.Add('HttpsPort', $this.HttpsPort)
                }
                
                if($this.TlsClientPort -ne $null){
                    $WapSettings.Add('TlsClientPort', $this.TlsClientPort)
                }

                Install-WebApplicationProxy @WapSettings

                if($this.ADFSTokenAcceptanceDurationSec -ne $null -or $this.UserIdleTimeoutSec -ne $null -or $this.UserIdleTimeoutAction -ne $null){
                    
                    if($this.ADFSTokenAcceptanceDurationSec -ne $null){
                        $WapSettings.Add('ADFSTokenAcceptanceDurationSec', $this.ADFSTokenAcceptanceDurationSec)
                    }
                    
                    if($this.UserIdleTimeoutSec -ne $null){
                        $WapSettings.Add('UserIdleTimeoutSec', $this.UserIdleTimeoutSec)
                    }

                    if($this.UserIdleTimeoutAction -ne $null){
                        $WapSettings.Add('UserIdleTimeoutAction', $this.UserIdleTimeoutAction)
                    }

                    Set-WebApplicationProxyConfiguration @WapSettings
                }
            }

            if ($WapConfiguration) {
                #Check certificate configuration
                $updateCertificates = $false
                try{
                    $certificates = Get-WebApplicationProxySslCertificate
                    $certificates | ForEach-Object {
                        if($_.CertificateHash -ne $this.CertificateThumbprint){
                            $updateCertificates = $true
                        }
                    }
                }
                catch{
                    $updateCertificates = $true
                }
               

                if($updateCertificates){
                    Set-WebApplicationProxySslCertificate -Thumbprint $this.CertificateThumbprint
                }

                if($this.ADFSTokenAcceptanceDurationSec -ne $null -or $this.UserIdleTimeoutSec -ne $null -or $this.UserIdleTimeoutAction -ne $null){
                    $WapSettings = @{}

                    if($this.ADFSTokenAcceptanceDurationSec -ne $null){
                        $WapSettings.Add('ADFSTokenAcceptanceDurationSec', $this.ADFSTokenAcceptanceDurationSec)
                    }
                    
                    if($this.UserIdleTimeoutSec -ne $null){
                        $WapSettings.Add('UserIdleTimeoutSec', $this.UserIdleTimeoutSec)
                    }

                    if($this.UserIdleTimeoutAction -ne $null){
                        $WapSettings.Add('UserIdleTimeoutAction', $this.UserIdleTimeoutAction)
                    }

                    Set-WebApplicationProxyConfiguration @WapSettings
                }
            }
        }

        if ($this.Ensure -eq [Ensure]::Absent) {
            # It is not actually possible to unconfigure WAP, so we do nothing

        }

        return
	}

	[bool] Test()
	{
        # Assume compliance by default
        $Compliant = $true


        Write-Verbose -Message 'Testing for presence of Web Application Proxy.'

        try {
            $WapConfiguration = Get-WebApplicationProxyConfiguration -ErrorAction Stop
        }
        catch {
            $Compliant = $false
            return $Compliant
        }

        if ($this.Ensure -eq 'Present') {
            Write-Verbose -Message 'Checking for correct ADFS service configuration.'
			
            if (-not($WapConfiguration.ADFSUrl.ToLower() -contains $this.FederationServiceName.ToLower())) {
                Write-Verbose -Message 'ADFS Service Name doesn''t match the desired state.'
                $Compliant = $false
            }

            try{
                $certificates = Get-WebApplicationProxySslCertificate
                $certificates | ForEach-Object {
                    if($_.CertificateHash -ne $this.CertificateThumbprint){
                        $Compliant = $false
                    }
                }
            }
            catch{
                $Compliant = $false
            }

            if($this.ADFSTokenAcceptanceDurationSec -ne $WapConfiguration.ADFSTokenAcceptanceDurationSec){
                $Compliant = $false
            }
            
            if($this.UserIdleTimeoutSec -ne $WapConfiguration.UserIdleTimeoutSec){
                $Compliant = $false
            }

            if($this.UserIdleTimeoutAction -ne $WapConfiguration.UserIdleTimeoutAction){
                $Compliant = $false
            }

        }

        if ($this.Ensure -eq 'Absent') {
            Write-Verbose -Message 'Checking for absence of WAP Configuration.'
            if ($WapConfiguration) {
                Write-Verbose -Message
                $Compliant = $false
            }
        }

        return $Compliant
	}

}
