enum Ensure {
    Absent
    Present
}

enum ExternalPreauthentication {
    PassThrough
    ADFS
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
    The ADFSRelyingPartyID property define the ADFS relying party ID of the application. It is required only if ExternalPreauthentication is ADFS
    #>
    [DscProperty()]
    [string] $ADFSRelyingPartyID

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
                if($this.ADFSRelyingPartyID -ne $Properties.ADFSRelyingPartyID){
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
                $ADFSRelyingPartyName = Get-ADFSRelyingPartyName $this.ADFSRelyingPartyID
                $WapWebsiteInfo.Add('ADFSRelyingPartyName', $ADFSRelyingPartyName)
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
