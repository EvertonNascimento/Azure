param(
    [string]
    $gatewayKey,
    $sub,
    $rg,
    $stacc,
    $container
)

# init log setting
$logLoc = "$env:SystemDrive\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\"
if (! (Test-Path($logLoc))) {
    New-Item -path $logLoc -type directory -Force
}
$logPath = "$logLoc\tracelog.log"
"Start to excute gatewayInstall.ps1. `n" | Out-File $logPath

function Now-Value() {
    return (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}

function Throw-Error([string] $msg) {
    try {
        throw $msg
    } 
    catch {
        $stack = $_.ScriptStackTrace
        Trace-Log "DMDTTP is failed: $msg`nStack:`n$stack"
    }

    throw $msg
}

function Trace-Log([string] $msg) {
    $now = Now-Value
    try {
        "${now} $msg`n" | Out-File $logPath -Append
    }
    catch {
        #ignore any exception during trace
    }

}

function Run-Process([string] $process, [string] $arguments) {
    Write-Verbose "Run-Process: $process $arguments"
	
    $errorFile = "$env:tmp\tmp$pid.err"
    $outFile = "$env:tmp\tmp$pid.out"
    "" | Out-File $outFile
    "" | Out-File $errorFile	

    $errVariable = ""

    if ([string]::IsNullOrEmpty($arguments)) {
        $proc = Start-Process -FilePath $process -Wait -Passthru -NoNewWindow `
            -RedirectStandardError $errorFile -RedirectStandardOutput $outFile -ErrorVariable errVariable
    }
    else {
        $proc = Start-Process -FilePath $process -ArgumentList $arguments -Wait -Passthru -NoNewWindow `
            -RedirectStandardError $errorFile -RedirectStandardOutput $outFile -ErrorVariable errVariable
    }
	
    $errContent = [string] (Get-Content -Path $errorFile -Delimiter "!!!DoesNotExist!!!")
    $outContent = [string] (Get-Content -Path $outFile -Delimiter "!!!DoesNotExist!!!")

    Remove-Item $errorFile
    Remove-Item $outFile

    if ($proc.ExitCode -ne 0 -or $errVariable -ne "") {		
        Throw-Error "Failed to run process: exitCode=$($proc.ExitCode), errVariable=$errVariable, errContent=$errContent, outContent=$outContent."
    }

    Trace-Log "Run-Process: ExitCode=$($proc.ExitCode), output=$outContent"

    if ([string]::IsNullOrEmpty($outContent)) {
        return $outContent
    }

    return $outContent.Trim()
}

function Download-Gateway([string] $url, [string] $gwPath) {
    try {
        $ErrorActionPreference = "Stop";
        $client = New-Object System.Net.WebClient
        $client.DownloadFile($url, $gwPath)
        Trace-Log "Download gateway successfully. Gateway loc: $gwPath"
    }
    catch {
        Trace-Log "Fail to download gateway msi"
        Trace-Log $_.Exception.ToString()
        throw
    }
}

function Download-Java([string] $url, [string] $jvPath) {
    try {
        $ErrorActionPreference = "Stop";
        $client = New-Object System.Net.WebClient
        $client.DownloadFile($url, $jvPath)
        Trace-Log "Download java successfully. Gateway loc: $jvPath"
    }
    catch {
        Trace-Log "Fail to download java"
        Trace-Log $_.Exception.ToString()
        throw
    }
}

function Download-Config([string] $url, [string] $jvPath) {
    try {
        $ErrorActionPreference = "Stop";
        $client = New-Object System.Net.WebClient
        $client.DownloadFile($url, $jvPath)
        Trace-Log "Download java successfully. Gateway loc: $jvPath"
    }
    catch {
        Trace-Log "Fail to download config"
        Trace-Log $_.Exception.ToString()
        throw
    }
}


function Install-Gateway([string] $gwPath) {
    if ([string]::IsNullOrEmpty($gwPath)) {
        Throw-Error "Gateway path is not specified"
    }

    if (!(Test-Path -Path $gwPath)) {
        Throw-Error "Invalid gateway path: $gwPath"
    }
	
    Trace-Log "Start Gateway installation"
    Run-Process "msiexec.exe" "/i gateway.msi INSTALLTYPE=AzureTemplate /quiet /norestart"		
	
    Start-Sleep -Seconds 30	

    Trace-Log "Installation of gateway is successful"
}


function Install-Java([string] $jvPath) {
    if ([string]::IsNullOrEmpty($jvPath)) {
        Throw-Error "Gateway path is not specified"
    }

    if (!(Test-Path -Path $jvPath)) {
        Throw-Error "Invalid gateway path: $jvPath"
    }
	
    Trace-Log "Start Gateway installation"

    Run-Process $jvPath "INSTALLCFG=C:\Packages\config.cfg"

    Start-Sleep -Seconds 30	

    Trace-Log "Installation of java is successful"
}


function Get-RegistryProperty([string] $keyPath, [string] $property) {
    Trace-Log "Get-RegistryProperty: Get $property from $keyPath"
    if (! (Test-Path $keyPath)) {
        Trace-Log "Get-RegistryProperty: $keyPath does not exist"
    }

    $keyReg = Get-Item $keyPath
    if (! ($keyReg.Property -contains $property)) {
        Trace-Log "Get-RegistryProperty: $property does not exist"
        return ""
    }

    return $keyReg.GetValue($property)
}

function Get-InstalledFilePath() {
    $filePath = Get-RegistryProperty "hklm:\Software\Microsoft\DataTransfer\DataManagementGateway\ConfigurationManager" "DiacmdPath"
    if ([string]::IsNullOrEmpty($filePath)) {
        Throw-Error "Get-InstalledFilePath: Cannot find installed File Path"
    }
    Trace-Log "Gateway installation file: $filePath"

    return $filePath
}

function Register-Gateway([string] $instanceKey) {
    Trace-Log "Register Agent"
    $filePath = Get-InstalledFilePath
    Run-Process $filePath "-era 8060"
    Run-Process $filePath "-k $instanceKey"
    Trace-Log "Agent registration is successful!"
}



Trace-Log "Log file: $logLoc"
$uri = "https://binfordeploy.blob.core.windows.net/binaries/IntegrationRuntime_4.7.7383.1.msi"
$urij = "https://binfordeploy.blob.core.windows.net/binaries/jre-8u251-windows-x64.exe"
$uric = "https://binfordeploy.blob.core.windows.net/binaries/config.txt"

Trace-Log "Gateway download fw link: $uri"
$gwPath = "$PWD\gateway.msi"
$jvPath = "C:\Packages\jre.exe"
$cfPath = "C:\Packages\config.cfg"
Trace-Log "Gateway download location: $gwPath"

Download-Gateway $uri $gwPath

Install-Gateway $gwPath
Download-Java $urij $jvPath
Download-Config $uric $cfPath
Install-Java $jvPath
#Register-Gateway $gatewayKey




###########################################################HDIONDEMAND############################################################################################

write-host "`n  ## NODEJS INSTALLER ## `n"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
### CONFIGURATION
# nodejs
#v14.15.4
$version = "v14.15.4"
#https://nodejs.org/dist/v14.15.4/node-v14.15.4-x64.msi
$url = "https://nodejs.org/dist/$version/node-$version-x64.msi"
    
# activate / desactivate any install
$install_node = $TRUE
$install_python = $TRUE
    
write-host "`n----------------------------"
write-host " system requirements checking  "
write-host "----------------------------`n"
    
### require administator rights
    
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    write-Warning "This setup needs admin permissions. Please run this file as admin."     
    break
}
    
### nodejs version check
    
if (Get-Command node -errorAction SilentlyContinue) {
    $current_version = (node -v)
}
     
#if ($current_version) {
#    write-host "[NODE] nodejs $current_version already installed"
#    $confirmation = read-host "Are you sure you want to replace this version ? [y/N]"
#    if ($confirmation -ne "y") {
#        $install_node = $FALSE
#    }
#}
    
    
if ($install_node) {
        
    ### download nodejs msi file
    # warning : if a node.msi file is already present in the current folder, this script will simply use it
            
    write-host "`n----------------------------"
    write-host "  nodejs msi file retrieving  "
    write-host "----------------------------`n"
    
    $filename = "node.msi"
    $node_msi = "$PSScriptRoot\$filename"
        
    #$download_node = $TRUE
    
    #if (Test-Path $node_msi) {
    #   $confirmation = read-host "Local $filename file detected. Do you want to use it ? [Y/n]"
    #    if ($confirmation -eq "n") {
    #        $download_node = $FALSE
    #    }
    #}
    
    #if ($download_node) {
    write-host "[NODE] downloading nodejs install"
    write-host "url : $url"
    $start_time = Get-Date
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($url, $node_msi)
    write-Output "$filename downloaded"
    write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"
    #} else {
    #    write-host "using the existing node.msi file"
    #}
    
    ### nodejs install
    
    write-host "`n----------------------------"
    write-host " nodejs installation  "
    write-host "----------------------------`n"
    
    write-host "[NODE] running $node_msi"
    Start-Process $node_msi -ArgumentList "/quiet " -Wait
        
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User") 
        
}
else {
    write-host "Proceeding with the previously installed nodejs version ..."
}
    
    
write-host "`n  ## Python INSTALLER ## `n"
    
# Python
#v14.15.4
$version = "v14.15.4"
#https://nodejs.org/dist/v14.15.4/node-v14.15.4-x64.msi
$pythonurl = "https://www.python.org/ftp/python/3.9.1/python-3.9.1-amd64.exe"
    
if ($install_python) {
        
    ### download nodejs msi file
    # warning : if a node.msi file is already present in the current folder, this script will simply use it
            
    write-host "`n----------------------------"
    write-host "  python file retrieving  "
    write-host "----------------------------`n"
    
    $filename = "python.exe"
    $python_exe = "$PSScriptRoot\$filename"
        
    #$download_node = $TRUE
    
    #if (Test-Path $node_msi) {
    #   $confirmation = read-host "Local $filename file detected. Do you want to use it ? [Y/n]"
    #    if ($confirmation -eq "n") {
    #        $download_node = $FALSE
    #    }
    #}
    
    #if ($download_node) {
    write-host "[Python] downloading nodejs install"
    write-host "url : $pythonurl"
    $start_time = Get-Date
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($pythonurl, $python_exe)
    write-Output "$filename downloaded"
    write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"
    #} else {
    #    write-host "using the existing node.msi file"
    #}
    
    ### nodejs install
    
    write-host "`n----------------------------"
    write-host " python installation  "
    write-host "----------------------------`n"
    
    write-host "[PYTHON] running $python_exe"
    Start-Process $python_exe -ArgumentList "/quiet InstallAllUsers=0 PrependPath=1 Include_test=0" -Wait 
        
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User") 
        
}
else {
    write-host "Proceeding with the previously installed python version ..."
}
    

Function DownloadBlobContents {  
    param(
        $stname,
        $sub,
        $rg,
        $target,
        $container
        
    )
    

    Write-Host -ForegroundColor Green "Download blob contents from storage container.."    
    ## Get the storage account  
    $storageAcc = Get-AzStorageAccount -ResourceGroupName $rg -Name $stname 
    ## Get the storage account key 
    $stkeys = Get-AzStorageAccountKey -ResourceGroupName $rg -AccountName $stname
    ## Get the storage account context  
    $ctx = New-AzStorageContext -StorageAccountName $stname -StorageAccountKey $stkeys[0].value
    ## Get all the containers  
    #$containers=Get-AzStorageContainer -Context $ctx   
    ## Loop through the containers  
    ## check if folder exists  
    #$folderPath=$downloadPath+"\"+$container.Name  
    Write-Host -ForegroundColor Magenta $container "-downloading contents"  
    ## Get the blob contents from the container  
    $blobContents = Get-AzStorageBlob -Container $container  -Context $ctx  
    foreach ($blobContent in $blobContents) {  
        ## Download the blob content  
        Get-AzStorageBlobContent -Container $container  -Context $ctx -Blob $blobContent.Name -Destination $target -Force  
    }  
          
        
} 
    

function Install-HDIONDEMAND ([string] $sub, $rg, $stacc, $container) {
    #downloadazfunctions
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser 
    Install-Module -Name PowerShellGet -Force -Scope CurrentUser -AllowClobber
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    Install-Module -Name Az -AllowClobber -Scope CurrentUser | Import-Module
    #Get-InstalledModule -Name Az -AllVersions
    #Start-Sleep -Seconds 30 q
    
    #$sub = "8aab2f07-7d43-4bab-8704-4dc764ee6190"
    #az principal information
    $azureAplicationId = "e5f3fc75-5a98-4438-8008-1311593099e2"
    $azureTenantId = "5d471751-9675-428d-917b-70f44f9630b0"
    $azurePassword = ConvertTo-SecureString "RnhHKNZbl02t_jucWUa84_EU.ZQCP_3RwJ" -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($azureAplicationId , $azurePassword)
    Connect-AzAccount -Credential $psCred -TenantId $azureTenantId  -ServicePrincipal
    
    

    #till i find a storage account to test.
    #Connect-AzAccount
    Set-AzContext -SubscriptionId $sub
    #$stname = "devtesthdisabs"
    #$rg = "DHUB_GPA-DEV-SAS"
    #$stname = $stacc


    #fazer isto via powershell
    $stkeys = Get-AzStorageAccountKey -ResourceGroupName $rg -AccountName $stacc
    $ctx = New-AzStorageContext -StorageAccountName $stacc -StorageAccountKey $stkeys[0].value
    
    mkdir azf
    $ContainerName = $container
    $BlobName = "hdiondemand"
    $target = "$PSScriptRoot\azf"
    
    #Get-AzureStorageBlobContent -Blob $BlobName -Container $ContainerName `
    #-Destination $target -Context $ctx
    
    DownloadBlobContents -stname $stacc -sub $sub -rg $rg -target $target -container $ContainerName
    Set-Location azf
    
    Expand-Archive .\hdiondemand.zip -DestinationPath .
    
    Write-Host "CREATING PARAMETERS FILE"
    $planfile = "gpaplan.txt"
    $loc = (Get-Location).tostring()
    
    python create_parameters.py $planfile $loc
    
    npm i -g azure-functions-core-tools@3 --unsafe-perm true --force
    pip install virtualenv
    virtualenv .venv 
    .venv\scripts\activate
    #pip uninstall -y cffi
    #pip install cffi
    #func init --worker-runtime python
    func start --verbose true > azflogs.txt

}



Install-HDIONDEMAND $sub $rg $stacc $container
