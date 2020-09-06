<#
.Synopsis
    Connect RDP from PowerShell
.DESCRIPTION
    Automatic RDP Connection from PowerShell
.EXAMPLE
    New-RdpSession -Computer ts.contoso.com

 .NOTES
    Author: Andre Hohenstein -  https://github.com/AndreHohenstein
   
.COMPONENT
    RdpSession - https://github.com/AndreHohenstein/RdpSession
#>
function New-RdpSession
{
[CmdletBinding()]
Param
(
[Parameter(
Mandatory=$true,
ValueFromPipeline=$true)]
[string]$Computer
)

 Begin
 {
    if (Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {$_.EnhancedKeyUsageList -like "*1.3.6.1.4.1.311.80.1*"})
       {
        Write-Host "your DocumentEncryptionCertis is available" -ForegroundColor Green
        }
 
    else
         {
     $UserName    = Read-Host "Please enter your Username for DocumentEncryptionCert"
     $Usage      = "Encrypt"
     $Usage      = $Username + $Usage
     
     $cert = @{
     FriendlyName                = "$Usage"
     Subject                     = "CN=$Usage"
     KeyUsage                    = "KeyEncipherment","DataEncipherment"
     KeySpec                     = "KeyExchange"
     Type                        = "DocumentEncryptionCert"
     TextExtension               =  @('2.5.29.37={text}1.3.6.1.4.1.311.80.1')
     Provider                    = "Microsoft RSA SChannel Cryptographic Provider"
     KeyLength                   = "4096"
     KeyAlgorithm                = "RSA"
     HashAlgorithm               = "SHA512"
     KeyExportPolicy             = "Exportable"
     NotAfter                    = (Get-Date).AddMinutes(60)
     AlternateSignatureAlgorithm = $true
     CertStoreLocation           = "Cert:\CurrentUser\my"
               }

    New-SelfSignedCertificate @cert | Out-Null

# Export Certificat 
    $CertStoreLocation = Get-ChildItem 'Cert:\CurrentUser\My'
    $mycert            = $CertStoreLocation | Where-Object {$_.Subject -match "CN=$Usage"} 
    $mycert            | Export-Certificate -Type CERT `
                       -FilePath "$env:USERPROFILE\Documents\$Usage.cer" | Out-Null

# Import Certificat to Trusted Root CA:
    $cert              = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$env:USERPROFILE\Documents\$Usage.cer")
    $rootStore         = Get-Item 'Cert:\LocalMachine\Root'
    $rootStore.Open('ReadWrite')
    $rootStore.Add($cert)
    $rootStore.Close()
         }
}
    Process
    {
    
    $Usercert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {$_.EnhancedKeyUsageList -like "*1.3.6.1.4.1.311.80.1*"}

$Username   = Read-Host "Pleae enter your Username for RemoteHost"
$password   = Read-Host "Please enter your password" `
             -AsSecureString|ConvertFrom-SecureString |
              Protect-CmsMessage -To $Usercert.Thumbprint `
             -OutFile "$env:USERPROFILE\Documents\secureRDP.txt"
                                                    

$pass       = Get-CmsMessage -Path  "$env:USERPROFILE\Documents\secureRDP.txt" |
              Unprotect-CmsMessage -To $Usercert.Thumbprint |
              ConvertTo-SecureString

$cred       = New-Object System.Management.Automation.PSCredential ($Username,$pass)

$rdp        = $cred.GetNetworkCredential().Password

cmdkey /generic:Termsrv/$computer /user:$Username /pass:$rdp > $null

mstsc /v:$computer

    }
    End
     {
    Start-Sleep -s 5
    cmdkey /list | ForEach-Object{if($_ -like "*LegacyGeneric:target=Termsrv/*")
    {cmdkey /del:($_ -replace " ","" -replace "Ziel:","")}} | Out-Null

    Get-ChildItem Cert:\CurrentUser\My\  |
    Where-Object {$_.EnhancedKeyUsageList -like "*1.3.6.1.4.1.311.80.1*" -and $_.Subject -like "*Encrypt"} |
    Remove-Item
    
    Get-ChildItem Cert:\LocalMachine\Root|
    Where-Object {$_.EnhancedKeyUsageList -like "*1.3.6.1.4.1.311.80.1*" -and $_.Subject -like "*Encrypt"} |
    Remove-Item
        
    Remove-Item "$env:USERPROFILE\Documents\secureRDP.txt" -ErrorAction SilentlyContinue

    if (Test-Path "$env:USERPROFILE\Documents\secureRDP.txt")
    {Remove-Item -Path "$env:USERPROFILE\Documents\secureRDP.txt"}

    #Remove-Variable * -ErrorAction SilentlyContinue; Remove-Module *; $error.Clear(); Clear-Host

      }
}
