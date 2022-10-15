#Enroll Telegraf agents into vRops
#v1.0 vman.ch, 12.09.2022 - Initial Version

<#
    Usage .\vRopsTelegrafEnrol.ps1 -vRopsAddress 'vropsa01.vman.ch' -vRopsUser 'telegrafenrol' -vRopsPassword 'vRopsPassword@123!' -VMName 'winsrv999999' -VMUser 'Administrator' -VMPass 'VMPassword@123!'
#>

param
(
    [String]$vRopsAddress,
    [String]$vRopsUser,
    [String]$vRopsPassword,
    [String]$VMName,
    [String]$VMUser,
    [String]$VMPass
)

#Error Action preference
$ErrorActionPreference = "Stop"

##Vars
$ScriptPath = (Get-Item -Path ".\" -Verbose).FullName

#Get Date / Time for vRops
[DateTime]$NowDate = (Get-date)
[int64]$NowDateEpoc = (([DateTimeOffset](Get-Date)).ToUniversalTime().ToUnixTimeMilliseconds())

#Cred

[securestring]$secstringPass = ConvertTo-SecureString $vRopsPassword -AsPlainText -Force
[pscredential]$vRopsCred = New-Object System.Management.Automation.PSCredential ($vRopsUser, $secstringPass)

Function New-vRopsToken {
    [CmdletBinding()]param(
        [PSCredential]$credentialFile,
        [string]$vROPSServer
    )
    
    if ($vROPSServer -eq $null -or $vROPSServer -eq '') {
        $vROPSServer = ""
    }

    $vROPSUser = $credentialFile.UserName
    $vROPSPassword = $credentialFile.GetNetworkCredential().Password 

    if ("TrustAllCertsPolicy" -as [type]) {} else {
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@ 
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }

    $BaseURL = "https://" + $vROPsServer + "/suite-api/api/"
    $BaseAuthURL = "https://" + $vROPsServer + "/suite-api/api/auth/token/acquire"
    $Type = "application/json"

    $AuthJSON =
    "{
      ""username"": ""$vROPSUser"",
      ""password"": ""$vROPsPassword""
    }"

    Try { $vROPSSessionResponse = Invoke-RestMethod -Method POST -Uri $BaseAuthURL -Body $AuthJSON -ContentType $Type }
    Catch {
        $_.Exception.ToString()
        $error[0] | Format-List -Force
    }

    $vROPSSessionHeader = @{"Authorization"="vRealizeOpsToken "+$vROPSSessionResponse.'auth-token'.token 
    "Accept"="application/xml"}
    $vROPSSessionHeader.add("X-vRealizeOps-API-use-unsupported","true")
    return $vROPSSessionHeader
}

#Take all certs.
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


Function GetObject([String]$vRopsObjName, [String]$resourceKindKey, [String]$vRopsServer, $vRopsToken){

$vRopsObjName = $vRopsObjName -replace ' ','%20'

[xml]$Checker = Invoke-RestMethod -Method GET -Uri "https://$vRopsServer/suite-api/api/resources?resourceKind=$resourceKindKey&name=$vRopsObjName" -ContentType "application/xml" -Headers $vRopsToken

# Check if we get more than 1 result and apply some logic
    If ([Int]$Checker.resources.pageInfo.totalCount -gt '1') {

        $DataReceivingCount = $Checker.resources.resource.resourceStatusStates.resourceStatusState.resourceStatus -eq 'DATA_RECEIVING'

            If ($DataReceivingCount.count -gt 1){

             If ($Checker.resources.resource.ResourceKey.name -eq $vRopsObjName){

                ForEach ($Result in $Checker.resources.resource){

                    IF ($Result.resourceStatusStates.resourceStatusState.resourceStatus -eq 'DATA_RECEIVING'){



                    $CheckerOutput = New-Object PsObject -Property @{Name=$vRopsObjName; resourceId=$Result.identifier; resourceKindKey=$Result.resourceKey.resourceKindKey} 

                    Return $CheckerOutput
                    
                    }   
                }

              }
            }
            
            Else 
            {

            ForEach ($Result in $Checker.resources.resource){

                IF ($Result.resourceStatusStates.resourceStatusState.resourceStatus -eq 'DATA_RECEIVING'){

                    $CheckerOutput = New-Object PsObject -Property @{Name=$vRopsObjName; resourceId=$Result.identifier; resourceKindKey=$Result.resourceKey.resourceKindKeY}

                    Return $CheckerOutput
                    
                }   
            }
    }  
 }
    else
    {
    
    IF ($Checker.resources.resource.ResourceKey.name -eq $vRopsObjName ) {

        $CheckerOutput = New-Object PsObject -Property @{Name=$vRopsObjName; resourceId=$Checker.resources.resource.identifier; resourceKindKey=$Checker.resources.resource.resourceKey.resourceKindKey}

    }

    Return $CheckerOutput

    }
}

Function vRopsTelegrafAgentEnrol([String]$resourceID, [String]$vRopsServer, $vRopsToken, $ServerUser, $ServerPassword){


    $EnrollXML += @('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <ops:resource-credentials xmlns:ops="http://webservice.vmware.com/vRealizeOpsMgr/1.0/" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ops:resourceCredentials>
                <ops:resourceCredential resourceId="'+$resourceID+'" username="'+$ServerUser+'" password="'+$ServerPassword+'">
                    <ops:addRuntimeUser>true</ops:addRuntimeUser>
                </ops:resourceCredential>
            </ops:resourceCredentials>
        </ops:resource-credentials>')


    $EnrollRequest = Invoke-RestMethod -Method POST -uri "https://$vRopsServer/suite-api/api/applications/agents" -Body $([xml]$EnrollXML) -ContentType "application/xml;charset=utf-8" -Headers $vRopsToken

    $StatusURL = ("https://$vRopsServer"+[String]$($EnrollRequest.'agent-task-statuses'.taskStatuses.taskStatus.links.link.href))

        If ($EnrollRequest.'agent-task-statuses'.taskStatuses.taskStatus.links.link.href){

        Write-Host "Install TaskID: $($EnrollRequest.'agent-task-statuses'.taskStatuses.taskStatus.taskID)"

        $AgentInstallStatus = Invoke-RestMethod -Method GET -uri $StatusURL -ContentType "application/xml;charset=utf-8" -Headers $vRopsToken


            While ($AgentInstallStatus.'bootstrap-status'.bootstrapObjectStatuses.'bootstrap-object-status'.stage -ne 'FINISHED'){

                $AgentInstallStatus = Invoke-RestMethod -Method GET -uri $("https://$vRopsServer/"+[String]$($EnrollRequest.'agent-task-statuses'.taskStatuses.taskStatus.links.link.href)) -ContentType "application/xml;charset=utf-8" -Headers $vRopsToken

                Sleep 10

                Write-host "Current Install State: $($AgentInstallStatus.'bootstrap-status'.bootstrapObjectStatuses.'bootstrap-object-status'.stage), Sleeping 10 Sec"

                If ($AgentInstallStatus.'bootstrap-status'.bootstrapObjectStatuses.'bootstrap-object-status'.stage -eq 'FAILED'){

                    Write-Error -Message 'Telegraf Agent Installation failed' -ErrorId 69

                }

            }

            Write-host "Telegraf Agent installed, woooowoooo metrics"
        }
}

#Generate Token
$vRopsAdminToken = New-vRopsToken $vRopsCred $vRopsAddress

#Lookup ResourceID
$resourceIDLookup = (GetObject $VMName 'VirtualMachine' $vRopsAddress $vRopsAdminToken).Resourceid

#Trigger Agent Install
$InstallAgent = vRopsTelegrafAgentEnrol $resourceIDLookup $vRopsAddress $vRopsAdminToken $VMUser $VMPass
