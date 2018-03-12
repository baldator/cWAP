enum Ensure {
    Absent
    Present
}

enum ExternalPreauthentication {
    PassThrough
    ADFS
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

        if( $name -eq 'IP:port' )
        {
            $binding = @{}
            $name = "IPPort"
            if( $value -notmatch '^(.*):(\d+)$' )
            {
                Write-Verbose 'Invalid IP address/port in netsh output: {0}.' -f $value
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

    [cWAPWebsite] Get() {

        Write-Verbose -Message 'Starting retrieving configuration for website {0}' -f $this.DisplayName

        try {
            Get-WebApplicationProxyApplication $this.DisplayName -ErrorAction Stop
        }
        catch {
            Write-Verbose -Message ('Error occurred while retrieving website configuration: {0}' -f $global:Error[0].Exception.Message)
        }

        Write-Verbose -Message 'Finished retrieving configuration for website {0}' -f $this.DisplayName
        return $this
    }

    [System.Boolean] Test() {
        # Assume compliance by default
        $Compliant = $true


        Write-Verbose -Message 'Testing for presence of WAP website {0}' -f $this.DisplayName

        try {
            $Properties = Get-WebApplicationProxyApplication $this.DisplayName -ErrorAction Stop
        }
        catch {
            $Compliant = $false
            return $Compliant
        }

        if ($this.Ensure -eq 'Present') {
            Write-Verbose -Message 'Checking for presence of WAP website.'
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

            if(!$compliant){
                Write-Verbose -Message 'WAP website doesn''t match the desired state.'         
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
            $WapWebsite = Get-AdfsProperties -ErrorAction stop
        }
        catch {
            $WapWebsite = $false
        }

        ### If WAP website shoud be present, then go ahead and create it.
        if ($this.Ensure -eq [Ensure]::Present) {
            $WapWebsiteInfo = @{
                Name                            = $this.DisplayName
                ExternalUrl                     = $this.ExternalUrl
                ExternalCertificateThumbprint   = $this.ExternalCertificateThumbprint
                BackendServerUrl                = $this.BackendServerUrl
                ExternalPreauthentication       = $this.ExternalPreauthentication
                EnableHTTPRedirect              = $this.EnableHTTPRedirect
            }

            if ($this.ExternalPreauthentication -eq "ADFS") {
                if($this.ADFSRelyingPartyName){
                    $WapWebsiteInfo.Add('ADFSRelyingPartyName', $this.ADFSRelyingPartyName)
                }
            }
            elseif ($this.BackendServerAuthenticationSPN) {
                $WapWebsiteInfo.Add('BackendServerAuthenticationSPN', $this.BackendServerAuthenticationSPN)
            }

            if (!$WapWebsite) {
                Write-Verbose -Message 'Creating WAP website {0}.' -f $this.DisplayName
                Add-WebApplicationProxyApplication @WapWebsiteInfo
            }

            if ($WapWebsite) {
                Write-Verbose -Message 'Editing WAP website {0}.' -f $this.DisplayName
                Set-WebApplicationProxyApplication @WapWebsiteInfo
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

	[cWAPConfiguration] Get()
	{
		Write-Verbose -Message 'Starting retrieving Web Applucation Proxy configuration.'

        try {
            $cWAPConfiguration=Get-WebApplicationProxyConfiguration -ErrorAction Stop
        }
        catch {
            Write-Verbose -Message ('Error occurred while retrieving Web Application Proxy configuration: {0}' -f $global:Error[0].Exception.Message)
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
                    FederationServiceTrustCredential = $this.Credential
                    CertificateThumbprint = $this.CertificateThumbprint
                    FederationServiceName = $this.FederationServiceName
                }
                Install-WebApplicationProxy @WapSettings
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
