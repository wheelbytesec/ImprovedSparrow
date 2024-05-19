[cmdletbinding()]
Param()

$ModuleArray = @("CloudConnect", "AzureAD", "MSOnline", "PSWriteHTML")

ForEach ($ReqModule in $ModuleArray) {
    If ($null -eq (Get-Module $ReqModule -ListAvailable -ErrorAction SilentlyContinue)) {
        Write-Verbose "Required module, $ReqModule, is not installed on the system."
        Write-Verbose "Installing $ReqModule from default repository"
        Install-Module -Name $ReqModule -Force
        Write-Verbose "Importing $ReqModule"
        Import-Module -Name $ReqModule
    } ElseIf ($null -eq (Get-Module $ReqModule -ErrorAction SilentlyContinue)) {
        Write-Verbose "Importing $ReqModule"
        Import-Module -Name $ReqModule
    }
}

$ExportDir = "$home\Desktop\ExportDir"
If (!(Test-Path $ExportDir)) {
    New-Item -Path $ExportDir -ItemType "Directory" -Force
}

$ReportData = @()
$ErrorLog = @()

Function Get-UALData {
    [cmdletbinding()]
    Param()

    Write-Verbose "Connecting to Exchange Online..."
    Connect-EXO

    $EndDate = (Get-Date)
    $StartDate = (Get-Date).AddDays(-90)

    $LicenseQuestion = Read-Host 'Do you have an Office 365/Microsoft 365 E5/G5 license? Y/N'
    Switch ($LicenseQuestion) {
        Y {$LicenseAnswer = "Yes"}
        N {$LicenseAnswer = "No"}
    }
    $AppIdQuestion = Read-Host 'Would you like to investigate a certain application? Y/N'
    Switch ($AppIdQuestion) {
        Y {$AppIdInvestigation = "Yes"}
        N {$AppIdInvestigation = "No"}
    }
    If ($AppIdInvestigation -eq "Yes") {
        $SusAppId = Read-Host "Enter the application's AppID to investigate"
    } Else {
        Write-Host "Skipping AppID investigation"
    }

    Try {
        Write-Verbose "Searching for domain and federation settings modifications in the UAL."
        $DomainData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Set domain authentication", "Set federation settings on domain" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $DomainData -CsvName "Domain_Operations_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in domain settings search: $_"
    }

    Try {
        Write-Verbose "Searching for application modifications in the UAL."
        $AppData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Update application", "Update application ? Certificates and secrets management" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $AppData -CsvName "AppUpdate_Operations_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in application modifications search: $_"
    }

    Try {
        Write-Verbose "Searching for service principal modifications in the UAL."
        $SpData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Update service principal", "Add service principal credentials" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $SpData -CsvName "ServicePrincipal_Operations_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in service principal modifications search: $_"
    }

    Try {
        Write-Verbose "Searching for app role assignments in the UAL."
        $AppRoleData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Add app role assignment" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $AppRoleData -CsvName "AppRoleAssignment_Operations_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in app role assignments search: $_"
    }

    Try {
        Write-Verbose "Searching for OAuth consents in the UAL."
        $ConsentData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Add OAuth2PermissionGrant", "Consent to application" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $ConsentData -CsvName "Consent_Operations_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in OAuth consents search: $_"
    }

    Try {
        Write-Verbose "Searching for SAML token usage anomalies in the UAL."
        $SAMLData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "UserLoggedIn", "UserLoginFailed" -ResultSize 5000 -FreeText "16457" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $SAMLData -CsvName "SAMLToken_Operations_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in SAML token usage anomalies search: $_"
    }

    Try {
        Write-Verbose "Searching for PowerShell logins into mailboxes in the UAL."
        $PSMailboxData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailboxLogin" -FreeText "Powershell" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $PSMailboxData -CsvName "PSMailbox_Operations_Export" -WorkloadType "EXO2"
    } Catch {
        $ErrorLog += "Error in PowerShell logins search: $_"
    }

    Try {
        Write-Verbose "Searching for PowerShell logins using known PS application IDs in the UAL."
        $PSLoginData1 = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -FreeText "a0c73c16-a7e3-4564-9a95-2bdf47383716" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $PSLoginData1 -CsvName "PSLogin_Operations_Export" -WorkloadType "AAD"
        $PSLoginData2 = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -FreeText "1b730954-1685-4b74-9bfd-dac224a7b894" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $PSLoginData2 -CsvName "PSLogin_Operations_Export" -WorkloadType "AAD" -AppendType "Append"
        $PSLoginData3 = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "UserLoggedIn", "UserLoginFailed" -FreeText "WinRM" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $PSLoginData3 -CsvName "PSLogin_Operations_Export" -WorkloadType "AAD" -AppendType "Append"
    } Catch {
        $ErrorLog += "Error in PowerShell logins using known PS application IDs search: $_"
    }

    If ($AppIdInvestigation -eq "Yes") {
        If ($LicenseAnswer -eq "Yes") {
            Try {
                Write-Verbose "Searching for $SusAppId in the MailItemsAccessed operation in the UAL."
                $SusMailItems = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 5000 -FreeText $SusAppId -Verbose | Select-Object -ExpandProperty AuditData | Convertfrom-Json
                Export-UALData -UALInput $SusMailItems -CsvName "MailItems_Operations_Export" -WorkloadType "EXO"
            } Catch {
                $ErrorLog += "Error in MailItemsAccessed search: $_"
            }
        } Else {
            Write-Host "MailItemsAccessed query will be skipped as it is not present without an E5/G5 license."
        }

        Try {
            Write-Verbose "Searching for $SusAppId in the FileAccessed and FileAccessedExtended operations in the UAL."
            $SusFileItems = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "FileAccessed", "FileAccessedExtended" -ResultSize 5000 -FreeText $SusAppId -Verbose | Select-Object -ExpandProperty AuditData | Convertfrom-Json
            Export-UALData -UALInput $SusFileItems -CsvName "FileItems_Operations_Export" -WorkloadType "Sharepoint"
        } Catch {
            $ErrorLog += "Error in FileAccessed search: $_"
        }
    }

    # New Detection Techniques
    Try {
        Write-Verbose "Searching for suspicious logins (unusual locations or devices)."
        $SuspiciousLogins = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "UserLoggedIn", "UserLoginFailed" -FreeText "UnusualLocation" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $SuspiciousLogins -CsvName "SuspiciousLogins_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in searching for suspicious logins: $_"
    }

    Try {
        Write-Verbose "Searching for privileged role assignments."
        $PrivilegedRoleAssignments = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Add member to role" -FreeText "GlobalAdministrator" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $PrivilegedRoleAssignments -CsvName "PrivilegedRoleAssignments_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in searching for privileged role assignments: $_"
    }

    Try {
        Write-Verbose "Searching for risky user activity."
        $RiskyUsers = Get-AzureADUserRiskDetection -All $true
        Export-UALData -UALInput $RiskyUsers -CsvName "RiskyUsers_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in searching for risky user activity: $_"
    }

    Try {
        Write-Verbose "Searching for changes to conditional access policies."
        $ConditionalAccessChanges = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Update policy" -FreeText "ConditionalAccess" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $ConditionalAccessChanges -CsvName "ConditionalAccessChanges_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in searching for changes to conditional access policies: $_"
    }

    Try {
        Write-Verbose "Searching for unusual application consents."
        $UnusualAppConsents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Add OAuth2PermissionGrant", "Consent to application" -FreeText "UnusualConsent" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        Export-UALData -UALInput $UnusualAppConsents -CsvName "UnusualAppConsents_Export" -WorkloadType "AAD"
    } Catch {
        $ErrorLog += "Error in searching for unusual application consents: $_"
    }
}

Function Get-AzureDomains {
    [cmdletbinding()]
    Param()

    Write-Verbose "Connecting to AzureAD..."
    Connect-AzureAD

    Try {
        Write-Verbose "Retrieving Azure AD domains..."
        $DomainData = Get-AzureADDomain
        $DomainArr = @()

        ForEach ($Domain in $DomainData) {
            $DomainProps = [ordered]@{
                AuthenticationType = $Domain.AuthenticationType
                AvailabilityStatus = $Domain.AvailabilityStatus
                ForceDeleteState = $Domain.ForceDeleteState
                IsAdminManaged = $Domain.IsAdminManaged
                IsDefault = $Domain.IsDefault
                IsInitial = $Domain.IsInitial
                IsRoot = $Domain.IsRoot
                IsVerified = $Domain.IsVerified
                Name = $Domain.Name
                State = $Domain.State
                SupportedServices = ($Domain.SupportedServices -join ';')
            }
            $DomainObj = New-Object -TypeName PSObject -Property $DomainProps
            $DomainArr += $DomainObj
        }
        $DomainArr | Export-Csv $home\Desktop\ExportDir\Domain_List.csv -NoTypeInformation
    } Catch {
        $ErrorLog += "Error in retrieving Azure AD domains: $_"
    }
}

Function Get-AzureSPAppRoles {
    [cmdletbinding()]
    Param()

    Write-Verbose "Connecting to AzureAD..."
    Connect-AzureAD

    Try {
        Write-Verbose "Retrieving Azure AD service principal app roles..."
        $SPArr = Get-AzureADServicePrincipal -All $true | Where-Object {$_.ServicePrincipalType -eq "Application"}

        $GraphSP = Get-AzureADServicePrincipal -All $true | Where-Object {$_.DisplayName -eq "Microsoft Graph"}
        $GraphAppRoles = $GraphSP.AppRoles | Select -Property AllowedMemberTypes, Id, Value

        $AppRolesArr = @()
        Foreach ($SP in $SPArr) {
            $GraphResource = Get-AzureADServiceAppRoleAssignedTo -ObjectId $SP.ObjectId | Where-Object {$_.ResourceDisplayName -eq "Microsoft Graph"}
            ForEach ($GraphObj in $GraphResource) {
                For ($i=0; $i -lt $GraphAppRoles.Count; $i++) {
                    If ($GraphAppRoles[$i].Id -eq $GraphObj.Id) {
                        $ListProps = [ordered]@{
                            ApplicationDisplayName = $GraphObj.PrincipalDisplayName
                            ClientID = $GraphObj.PrincipalId
                            Value = $GraphAppRoles[$i].Value
                        }
                    }
                }
                $ListObj = New-Object -TypeName PSObject -Property $ListProps
                $AppRolesArr += $ListObj
            }
        }
        $AppRolesArr | Export-Csv $home\Desktop\ExportDir\ApplicationGraphPermissions.csv -NoTypeInformation
    } Catch {
        $ErrorLog += "Error in retrieving Azure AD service principal app roles: $_"
    }
}

Function Export-UALData {
    Param(
        [Parameter(ValueFromPipeline=$True)]
        [Object[]]$UALInput,
        [Parameter()]
        [String]$CsvName,
        [Parameter()]
        [String]$WorkloadType,
        [Parameter()]
        [String]$AppendType
    )

    $DataArr = @()
    If ($WorkloadType -eq "AAD") {
        ForEach ($Data in $UALInput) {
            $DataProps = [ordered]@{
                CreationTime = $Data.CreationTime
                Id = $Data.Id
                Operation = $Data.Operation
                Organization = $Data.Organization
                RecordType = $Data.RecordType
                ResultStatus = $Data.ResultStatus
                LogonError = $Data.LogonError
                UserKey = $Data.UserKey
                UserType = $Data.UserType
                Version = $Data.Version
                Workload = $Data.Workload
                ClientIP = $Data.ClientIP
                ObjectId = $Data.ObjectId
                UserId = $Data.UserId
                AzureActiveDirectoryEventType = $Data.AzureActiveDirectoryEventType
                ExtendedProperties = ($Data.ExtendedProperties | ConvertTo-Json -Compress | Out-String).Trim()
                ModifiedProperties = (($Data.ModifiedProperties | ConvertTo-Json -Compress) -replace "\\r\\n" | Out-String).Trim()
                Actor = ($Data.Actor | ConvertTo-Json -Compress | Out-String).Trim()
                ActorContextId = $Data.ActorContextId
                ActorIpAddress = $Data.ActorIpAddress
                InterSystemsId = $Data.InterSystemsId
                IntraSystemId = $Data.IntraSystemId
                SupportTicketId = $Data.SupportTicketId
                Target = ($Data.Target | ConvertTo-Json -Compress | Out-String).Trim()
                TargetContextId = $Data.TargetContextId
            }
            $DataObj = New-Object -TypeName PSObject -Property $DataProps
            $DataArr += $DataObj
        }
    } ElseIf ($WorkloadType -eq "EXO") {
        ForEach ($Data in $UALInput) {
            $DataProps = [ordered]@{
                CreationTime = $Data.CreationTime
                Id = $Data.Id
                Operation = $Data.Operation
                OrganizationId = $Data.OrganizationId
                RecordType = $Data.RecordType
                ResultStatus = $Data.ResultStatus
                UserKey = $Data.UserKey
                UserType = $Data.UserType
                Version = $Data.Version
                Workload = $Data.Workload
                UserId = $Data.UserId
                AppId = $Data.AppId
                ClientAppId = $Data.ClientAppId
                ClientIPAddress = $Data.ClientIPAddress
                ClientInfoString = $Data.ClientInfoString
                ExternalAccess = $Data.ExternalAccess
                InternalLogonType = $Data.InternalLogonType
                LogonType = $Data.LogonType
                LogonUserSid = $Data.LogonUserSid
                MailboxGuid = $Data.MailboxGuid
                MailboxOwnerSid = $Data.MailboxOwnerSid
                MailboxOwnerUPN = $Data.MailboxOwnerUPN
                OperationProperties = ($Data.OperationProperties | ConvertTo-Json -Compress | Out-String).Trim()
                OrganizationName = $Data.OrganizationName
                OriginatingServer = $Data.OriginatingServer
                Folders = ((($Data.Folders | ConvertTo-Json -Compress).replace("\u003c", "")).replace("\u003e", "") | Out-String).Trim()
                OperationCount = $Data.OperationCount
            }
            $DataObj = New-Object -TypeName PSObject -Property $DataProps
            $DataArr += $DataObj
        }
    } ElseIf ($WorkloadType -eq "EXO2") {
        ForEach ($Data in $UALInput) {
            $DataProps = [ordered]@{
                CreationTime = $Data.CreationTime
                Id = $Data.Id
                Operation = $Data.Operation
                OrganizationId = $Data.OrganizationId
                RecordType = $Data.RecordType
                ResultStatus = $Data.ResultStatus
                UserKey = $Data.UserKey
                UserType = $Data.UserType
                Version = $Data.Version
                Workload = $Data.Workload
                ClientIP = $Data.ClientIP
                UserId = $Data.UserId
                ClientIPAddress = $Data.ClientIPAddress
                ClientInfoString = $Data.ClientInfoString
                ExternalAccess = $Data.ExternalAccess
                InternalLogonType = $Data.InternalLogonType
                LogonType = $Data.LogonType
                LogonUserSid = $Data.LogonUserSid
                MailboxGuid = $Data.MailboxGuid
                MailboxOwnerSid = $Data.MailboxOwnerSid
                MailboxOwnerUPN = $Data.MailboxOwnerUPN
                OrganizationName = $Data.OrganizationName
            }
            $DataObj = New-Object -TypeName PSObject -Property $DataProps
            $DataArr += $DataObj
        }
    }
    $CsvPath = "$ExportDir\$CsvName.csv"
    If ($AppendType -eq "Append") {
        $DataArr | Export-Csv -Path $CsvPath -NoTypeInformation -Append
    } Else {
        $DataArr | Export-Csv -Path $CsvPath -NoTypeInformation
    }
    $ReportData += $DataArr
}

Function Generate-Report {
    Param()

    Write-Verbose "Generating HTML report..."
    $ReportFile = "$ExportDir\AuditReport.html"
    
    $HTMLContent = New-HTML {
        New-HTMLContent -HeaderText "Unified Audit Log Report" -HeaderSize 2
        New-HTMLTable -DataTable $ReportData -HideFooter -DisplayAllProperties
        New-HTMLContent -HeaderText "Error Log" -HeaderSize 2
        New-HTMLTable -DataTable $ErrorLog -HideFooter -DisplayAllProperties
    } -ShowHTML -FilePath $ReportFile

    Write-Host "Report generated at: $ReportFile"
}

# Main Execution
Get-UALData
Get-AzureDomains
Get-AzureSPAppRoles
Generate-Report
