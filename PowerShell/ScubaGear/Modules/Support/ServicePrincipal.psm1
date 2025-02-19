function Compare-ScubaGearPermissions {
    <#
    .SYNOPSIS
        Compares the service principal permissions against the AppRoleIDs array.

    .DESCRIPTION
        This function will compare the service principal permissions against the AppRoleIDs array. If the service principal is missing any permissions, the function will return the missing permissions.

    .PARAMETER ServicePrincipalID
        Used to define the AppID of the service principal that will be checked for permissions.

    .PARAMETER AppRoleIDs
        The AppRoleIDs that are required for the ScubaGear application.

    .EXAMPLE
        Compare-ScubaGearPermissions -ServicePrincipalID "AppID" -AppRoleIDs $AppRoleIDs

        This example will compare the service principal permissions against the AppRoleIDs array.

    .NOTES
        Author         : ScubaGear Team
        Prerequisite   : PowerShell 5.1 or later
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalID,

        [Parameter(Mandatory = $false)]
        [object]$AppRoleIDs,

        [Parameter(Mandatory = $false)]
        [string[]]$Roles
    )

    if($Roles){
        # Assign the service principal to the directory roles
        $SPRoleAssignment = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($SP.Id)'"
        if($Null -ne $SPRoleAssignment){
            $ISGRRole = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $SPRoleAssignment.roleDefinitionId
        }

        if($Roles -notcontains $ISGRRole.DisplayName){
            $assignedRoles = @()

            ForEach ($Role in $Roles) {
                $RoleName = $Role
                $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'"
            }
            Write-Host "Service Pricipal missing role: $Roles" -foregroundcolor Yellow
            Write-Host ""
        }else{
            Write-Host "Service Principal already assigned to directory roles [$Roles] as specified in the permissions file." -foregroundcolor Yellow
        }
        return $roleDefinition.Id
    }else{
        $SPMissingPerms = @()
        $SPExtraPerms = @()
        # Check to see if the service principal is already assigned to the API permissions (Compare Service principal permissions against the AppRoleIDs array)
        $SPPerms = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalID

        if ($null -ne $SPPerms) {
            # Extract AppRoleID properties for comparison
            $AppRoleIDsList = $AppRoleIDs | Select-Object -ExpandProperty AppRoleID
            $SPPermsList = $SPPerms | Select-Object -ExpandProperty AppRoleId

            # Compare the AppRoleIDs array against the service principal permissions, then list the differences
            $Diff = Compare-Object -ReferenceObject $AppRoleIDsList -DifferenceObject $SPPermsList -IncludeEqual -ErrorAction SilentlyContinue

            # Determine if the service principal is missing any permissions
            $SPMissingPerms = $Diff | Where-Object {$_.SideIndicator -eq "<="}

            # Determine if the service principal has any extra permissions
            $SPExtraPerms = $Diff | Where-Object {$_.SideIndicator -eq "=>"}

            # Create a new array to store the permissions that are missing from the service principal, ensure that the permissions are unique and the resourceAPIAppId is included
            # Ensure $SPMissingPerms is unique
            $SPMissingPerms = $SPMissingPerms | Select-Object InputObject -Unique

            if ($null -ne $AppRoleIDs -and $null -ne $SPMissingPerms) {
                ForEach ($SPMissingPerm in $SPMissingPerms) {
                    # Find the matching object in $AppRoleIDs
                    $matchingAppRole = $AppRoleIDs | Where-Object { $_.AppRoleID -eq $SPMissingPerm.InputObject } | Select-Object -Unique

                    if ($matchingAppRole) {
                        # Add the resourceAPIAppId to the missing permissions from $AppRoleIDs
                        $SPMissingPerm | Add-Member -MemberType NoteProperty -Name resourceAPIAppId -Value $matchingAppRole.resourceAPIAppId -Force

                        # Include the leastPermissions value
                        $SPMissingPerm | Add-Member -MemberType NoteProperty -Name leastPermissions -Value $matchingAppRole.APIName -Force
                    }
                }
            }

            # Output the updated $SPMissingPerms
            $missingPermsCount = $SPMissingPerms.leastPermissions.Count

            if($missingPermsCount -eq 0){
                Write-Host "Service Principal permissions comparison completed, missing " -NoNewline
                Write-Host "[$missingPermsCount]" -ForegroundColor Green -NoNewline
                Write-Host " API permissions"
            }else{
                Write-Host "Service Principal permissions comparison completed, missing " -NoNewline
                Write-Host "[$missingPermsCount]" -ForegroundColor Red -NoNewline
                Write-Host " API permissions"
            }

            # Output the missing permissions
            ForEach ($MissingPerm in $SPMissingPerms) {
                Write-Host "Missing API Permission: $($MissingPerm.leastPermissions)" -foregroundcolor Yellow
            }

            if($SPExtraPerms){
                # Output the extra permissions
                Write-Host ""
                Write-Host "Service Principal has extra permissions:"

                ForEach ($ExtraPerm in $SPExtraPerms) {
                # Initialize a variable to store the API permission name
                $APIPermissionName = $null

                # Find match for $SPExtraPerms.InputObject in the $SPPerms array and output the ResourseID
                $ExtraSPPermsResourceID = ($SPPerms | Where-Object { $_.AppRoleId -eq $($ExtraPerm).InputObject}).ResourceID

                $graphServicePrincipal = Get-MgServicePrincipal -Filter "ID eq '$ExtraSPPermsResourceID'"

                # Retrieve the correct AppRole based on the ID
                $APIPermission = $graphServicePrincipal.AppRoles | Where-Object { $_.Id -eq $ExtraPerm.InputObject }

                # If a match is found, get the display name
                If ($APIPermission) {
                $APIPermissionName = $APIPermission.Value
                }

                # Output the results
                    If ($APIPermissionName) {
                        Write-Host "Extra API Permission: $APIPermissionName" -ForegroundColor Red
                    } Else {
                        Write-Host "No matching API permission found for ID: $($ExtraPerm).InputObject" -ForegroundColor Yellow
                    }
                }
            }
        } else {
            Write-Host "No service principal permissions found, skipping comparison."
        }
            return $SPMissingPerms
    }
}

function Set-ScubaGearRoles {
<#
.SYNOPSIS
    Assigns a service principal to the roles specified by the ScubaGearSPRole parameter.

.DESCRIPTION
    This function will assign a service principal to the roles specified by the ScubaGearSPRole parameter.

.PARAMETER ServicePrincipalID
    Used to define the AppID of the service principal that will be added to the roles specified by the ScubaGearSPRole parameter.

.PARAMETER ScubaGearSPRole
    The role that the service principal will be assigned to.

.EXAMPLE
    Set-ScubaGearRoles -ServicePrincipalID "AppID" -ScubaGearSPRole "ScubaGear Role"

    This example will assign the service principal with the specified AppID to the role specified by the ScubaGearSPRole parameter.

.NOTES
    Author         : ScubaGear Team
    Prerequisite   : PowerShell 5.1 or later
#>
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId,

        [Parameter(Mandatory = $true)]
        [string]$roleDefinitionID
    )

    try {
        $AssignGRRole = New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $ServicePrincipalId -RoleDefinitionId $roleDefinitionId -DirectoryScopeId "/"
        Write-Host "Assigned service principal to role:"
    } catch {
        Write-Host "Failed to assign service principal to role:"
    }
}

function Get-ScubaGearAppRoleIDs {
<#
.SYNOPSIS
    Retrieves AppRoleIDs for defined permissions within the appropriate environment. Some AppRoleIDs have different values in different environments.

.DESCRIPTION
    This function will retrieve the AppRoleIDs for the defined permissions within the appropriate environment. Some AppRoleIDs have different values in different environments. This function ensures we are retrieving the correct AppRoleIDs for the defined permissions relevant and environment.

.PARAMETER ScubaGearSPPermissions
    The permissions that are required for the ScubaGear application. Current permissions are defined in the ScubaGearPermissions.json file.

.EXAMPLE
    Get-ScubaGearAppRoleIDs -ScubaGearSPPermissions $ScubaGearSPPermissions

    This example will retrieve the AppRoleIDs for the defined permissions within the appropriate environment.

.NOTES
    Author         : ScubaGear Team
    Prerequisite   : PowerShell 5.1 or later
#>
    param (
        [Parameter(Mandatory = $true)]
        [object]$ScubaGearSPPermissions
    )

    $AppRoleIDs = @()

    foreach ($Permission in $ScubaGearSPPermissions) {
        try {
            $Filter = "AppId eq '" + $Permission.resourceAPIAppId + "'"
            $ProductResource = Get-MgServicePrincipal -Filter $Filter
            $ProductResourceID = $ProductResource.Id

            $APIPermissionNames = $Permission.leastPermissions

            foreach ($ID in $APIPermissionNames) {
                $AppRoleID = ($ProductResource.AppRoles | Where-Object { $_.Value -eq "$ID" }).id

                # Create a new object for each permission
                $AppRoleObject = New-Object -TypeName PSObject
                $AppRoleObject | Add-Member -MemberType NoteProperty -Name resourceAPIAppId -Value $Permission.resourceAPIAppId -Force
                $AppRoleObject | Add-Member -MemberType NoteProperty -Name APIName -Value $ID -Force
                $AppRoleObject | Add-Member -MemberType NoteProperty -Name AppRoleID -Value $AppRoleID -Force

                # Add the object to the array
                $AppRoleIDs += $AppRoleObject
            }
        } catch {
            Write-Host "Failed to retrieve $ProductName API Permission: $APIPermissionNames"
        }
    }

    return $AppRoleIDs
}

function Set-ScubaGearAPIPermissions {
<#
.SYNOPSIS
    Retrieves current permissions for a service principal and compares them to required ScubaGear permissions.

.DESCRIPTION
    This function will retrieve the current permissions for a service principal and compare them to the ScubaGear permissions. If the service principal is missing any permissions, the function will assign the missing permissions to the service principal.

.PARAMETER ServicePrincipalID
    Used to define the AppID of the service principal that will be checked for permissions.

.PARAMETER SPMissingPerms
    The missing permissions that will be assigned to the service principal.

.PARAMETER ScubaGearSPPermissions
    The permissions that are required for the ScubaGear application.

.PARAMETER SPPerms
    The permissions that are currently assigned to the service principal.

.EXAMPLE
    Set-ScubaGearAPIPermissions -ServicePrincipalID "AppID" -SPMissingPerms $SPMissingPerms -ScubaGearSPPermissions $ScubaGearSPPermissions -SPPerms $SPPerms

    This example will assign the missing permissions to the service principal with the specified AppID.

.NOTES
    Author         : ScubaGear Team
    Prerequisite   : PowerShell 5.1 or later
#>
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalID,

        [Parameter(Mandatory = $false)]
        [array]$SPMissingPerms,

        [Parameter(Mandatory = $true)]
        [array]$ScubaGearSPPermissions,

        [Parameter(Mandatory = $false)]
        [array]$SPPerms
    )

    # If there are differences, assign the service principal to the API permissions
    if ($null -ne $SPMissingPerms) {
        # Assign the missing permissions to the service principal that are in the $SPMissingPerms array
        try {
            foreach ($MissingPerm in $SPMissingPerms) {
                try {
                    $Filter = "AppId eq '" + $MissingPerm.resourceAPIAppId + "'"
                    $ProductResource = Get-MgServicePrincipal -Filter $Filter
                    $ProductResourceID = $ProductResource.Id

                    # Check to see if $permission.leastPermissions has more than one value if so ensure that the permissions are unique and not stored together
                    $AppRoleID = $MissingPerm.InputObject
                    $ProductName = $ProductResource.AppDisplayName

                    $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalID -PrincipalId $ServicePrincipalID -ResourceId $ProductResourceID -AppRoleId $AppRoleID
                    Write-Host "Assigned $ProductName API Permission: $($MissingPerm.leastPermissions)"
                } catch {
                    Write-Host -Message "Failed to assign missing $ProductName API Permission: $APIPermissionName"
                }
            }
        } catch {
            Write-Host "Failed to assign Service Principal to API permissions: $_.Exception.Message"
            throw
        }
    } elseif ($null -eq $SPPerms) {
        # Assign API permissions to the service principal if this is a fresh install
        try {
            foreach ($Permission in $ScubaGearSPPermissions) {
                $Filter = "AppId eq '" + $Permission.resourceAPIAppId + "'"
                $ProductResource = Get-MgServicePrincipal -Filter $Filter
                $ProductResourceID = $ProductResource.Id
                $APIPermissionName = $Permission.leastPermissions

                # Check to see if $permission.leastPermissions has more than one value if so ensure that the permissions are unique and not stored together
                $AppRoleID = ($ProductResource.AppRoles | Where-Object { $_.Value -eq "$APIPermissionName" }).id
                $ProductName = $ProductResource.AppDisplayName

                $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalID -PrincipalId $ServicePrincipalID -ResourceId $ProductResourceID -AppRoleId $AppRoleID
                Write-Host "Assigned $ProductName API Permission: $APIPermissionName"
            }
        } catch {
            Write-Host "Failed to assign Service Principal to API permissions: $_.Exception.Message"
            throw
        }
    } else {
        Write-Host "Service Principal already assigned to API permissions, skipping assignment."
    }
}

Function Get-ScubaGearAppPermissions {
<#
.SYNOPSIS
    Retrieves current permissions for a service principal and compares them to the ScubaGear permissions.

.DESCRIPTION
    This function will retrieve the current permissions for a service principal and compare them to the ScubaGear permissions. If the service principal is missing any permissions, the function will assign the missing permissions to the service principal.

.PARAMETER AppID
    Used to define the AppID of the service principal that will be checked for permissions. This is the Application (client) ID of the app registration.

.PARAMETER FixPermissionIssues
    Used to define whether the function will assign missing permissions to the service principal. This is a switch parameter and not ran by default.

.EXAMPLE
    Get-ScubaGearAppPermissions -AppID "AppID" -FixPermissionIssues

    This example will retrieve the permissions for the service principal with the specified AppID and assign any missing permissions.

.EXAMPLE
    Get-ScubaGearAppPermissions -AppID "AppID"

    This example will retrieve the permissions for the service principal with the specified AppID and return any missing permissions.

.NOTES
    Author         : ScubaGear Team
    Prerequisite   : PowerShell 5.1 or later
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppID,

        [Parameter(Mandatory = $false)]
        [switch]$FixPermissionIssues,

        [Parameter(Mandatory = $true)]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $True)]
        [string]$Environment
    )

    switch ($Environment.ToLower().Trim()) {
        "commercial" {
            $GraphEnvironment  = "Global"
        }
        "gcc" {
            $GraphEnvironment  = "Global"
        }
        "gcchigh" {
            $GraphEnvironment  = "USGov"
        }
        "dod" {
            $GraphEnvironment  = "USGovDoD"
        }
    }

    # Connect to Microsoft Graph
    try {
        $Null = Connect-MgGraph -Scopes "Application.ReadWrite.All" -Environment $GraphEnvironment
        Write-Host "Successfully connected to Microsoft Graph"
        Write-Host ""
    }
    catch {
        Write-Host "Failed to connect to Microsoft Graph: $_.Exception.Message"
    }

    # Required Permissions for the ScubaGear Application
    $ScubaGearSPPermissions = Get-ScubaGearEntraRedundantPermissions -ServicePrincipal | sort -Property LeastPermissions,resourceAPiAppID -Unique

    # Required Roles for the ScubaGear Application
    $ScubaGearSPRole = Get-ScubaGearPermissions -OutAs role

    # Retrieve the permissions from existing service principal
    $SP = Get-MgServicePrincipal -filter "appId eq '$AppID'"
    $SPPerms = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id

    # Create an object to store the permissions
    $AppRoleIDs = Get-ScubaGearAppRoleIDs -ScubaGearSPPermissions $ScubaGearSPPermissions

    # Compare the service principal permissions against the AppRoleIDs array
    $SPMissingPerms = Compare-ScubaGearPermissions -ServicePrincipalID $SP.ID -AppRoleIDs $AppRoleIDs

    # Compare the service principal to the directory roles
    $SPRoleAssignment = Compare-ScubaGearPermissions -ServicePrincipalID $SP.ID -Roles $ScubaGearSPRole

    # If there are differences, assign the service principal to the API permissions if the -FixPermissionIssues switch is used
    if($PSBoundParameters.ContainsKey('FixPermissionIssues') -and $null -ne $SPMissingPerms){
        # Assign the missing permissions to the service principal
        $AssignPerms = Set-ScubaGearAPIPermissions -ServicePrincipalID $SP.ID -SPMissingPerms $SPMissingPerms -ScubaGearSPPermissions $ScubaGearSPPermissions -SPPerms $SPPerms

    }elseif($PSBoundParameters.ContainsKey('FixPermissionIssues') -and (($Null -eq $SPPerms) -or $SPRoleAssignment)){
        if($Null -eq $SPPerms){
            # Assign the service principal to the required permissions
            $AssignPerms = Set-ScubaGearAPIPermissions -ServicePrincipalID $SP.ID -ScubaGearSPPermissions $ScubaGearSPPermissions
        }elseif($SPRoleAssignment){
            # Assign the service principal to the required roles
            $AssignRoles = Set-ScubaGearRoles -ServicePrincipalID $SP.ID -roleDefinitionID $SPRoleAssignment
        }
    }else{
       # No missing permissions found, skipping assignment.
    }
}

function New-ScubaGearServicePrincipal {
<#
.SYNOPSIS
    This is used to Create the Scuba Application for use with ScubaGear.

.DESCRIPTION
    This will create the necessary Application and Service Principal permissions to run ScubaGear in non-interactive mode.

.PARAMETER CertName
    Used to define your certificate name that will be stored on your device and used to interface with the ScubaGear application created in this script. The default is "ScubaGearCert"

.PARAMETER AddPowerAppsAccount
    Adds the Optional build Out for PowerApps.  If you are not using PowerApps, do not use this parameter

.PARAMETER Environment
    Used to define the environment that the application will be created in. The options are commercial, gcc, gcchigh, dod

.PARAMETER ServicePrincipalName
    Used to define the name of the Service Principal that will be created. The default is "ScubaGear Application"

.EXAMPLE
    To run without PowerApps and create in commercial
    New-ScubaGearServicePrincipal -CertName "NameOfYourCert" -environment commercial

.EXAMPLE
    To Run with PowerApps and create in GCC High
    New-ScubaGearServicePrincipal -CertName "NameOfYourCert" -AddPowerAppsAccount -environment gcchigh

.EXAMPLE
    To Run with PowerApps and set service principal name to "MyServicePrincipal" and create in dod
    New-ScubaGearServicePrincipal -AddPowerAppsAccount -environment dod -ServicePrincipalName "MyServicePrincipal"

.NOTES
    Author         : ScubaGear Team
    Prerequisite   : PowerShell 5.1 or later
#>

[cmdletbinding()]
param (
    [Parameter(Mandatory=$false)]
    [switch]$AddPowerAppsAccount,

    [Parameter(Mandatory=$false)]
    [string]$CertName = "ScubaGearCert",

    [Parameter(Mandatory=$true)]
    [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $True)]
    [string]$Environment,

    [Parameter(Mandatory=$false)]
    [ValidateLength(0, 120)]
    [string]$ServicePrincipalName = "ScubaGear Application"
)

switch ($Environment.ToLower().Trim()) {
    "commercial" {
        $GraphEnvironment  = "Global"
        $PowerAppsEndpoint = 'prod'
    }
    "gcc" {
        $GraphEnvironment  = "Global"
        $PowerAppsEndpoint = 'usgov'
    }
    "gcchigh" {
        $GraphEnvironment  = "USGov"
        $PowerAppsEndpoint = 'usgovhigh'

    }
    "dod" {
        $GraphEnvironment  = "USGovDoD"
        $PowerAppsEndpoint = 'dod'
    }
}

Try {
    # Connect to Microsoft Graph
    try {
        $Null = Connect-MgGraph -Scopes "Application.ReadWrite.All, RoleManagement.ReadWrite.Directory" -Environment $GraphEnvironment
        Write-Host "Successfully connected to Microsoft Graph"
    }
    catch {
        Write-Host "Failed to connect to Microsoft Graph: $_.Exception.Message"
    }

    # Required Permissions for the ScubaGear Application
    $requiredResourcePermissions = Get-ScubaGearEntraRedundantPermissions -ServicePrincipal | sort -Property LeastPermissions,resourceAPiAppID -Unique

    # Required Roles for the ScubaGear Application
    $PermissionFileRole = Get-ScubaGearPermissions -OutAs role

    try {
        $app = New-MgApplication -DisplayName $ServicePrincipalName

        # Azure doesn't always update immediately, make sure app exists before we try to update its config
        $appExists = $false
        while (!$appExists) {
            Start-Sleep -Seconds 2
            $appExists = Get-MgApplication -ApplicationId $app.Id
        }
        Write-Host ""
        Write-Host "Service Principal Application (Client) ID: $($app.Id)" -foregroundcolor Yellow
        Write-Host ""

        $sp = New-MgServicePrincipal -AppId $app.AppId

        # Assign the service principal to the required permissions
        try {
            ForEach($Permission in $requiredResourcePermissions){

                $Filter = "AppId eq '" + $Permission.resourceAPIAppId + "'"
                $ProductResource = (Get-MgServicePrincipal -Filter $Filter)
                $ProductResourceID = $ProductResource.Id
                $APIPermissionName = $Permission.leastPermissions

                # Check to see if $permission.leastPermissions has more than one value if so ensure that the permissions are unique and not stored together
                $AppRoleID = ($ProductResource.AppRoles | Where-Object {$_.Value -eq "$APIPermissionName"}).id
                $ProductName = $ProductResource.AppDisplayName

                $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.ID -PrincipalId $SP.ID -ResourceId $ProductResourceID -AppRoleId $AppRoleID
                Write-Host "Assigned $ProductName API Permission: $APIPermissionName" -foregroundcolor Green
            }
        }catch {
            Write-Host "Failed to assign Service Principal to API permissions: $_.Exception.Message"
            throw
        }

        # Assign service principal to the required roles
        try {
            $assignedRoles = @()

            ForEach ($Role in $PermissionFileRole) {
                $RoleName = $Role
                $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'"
                Try{
                    $null = New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $SP.ID -RoleDefinitionId $roleDefinition.Id -DirectoryScopeId "/"
                    $assignedRoles += $RoleName
                }Catch{
                    Write-Host "Failed to assign service principal to role: $RoleName" -foregroundcolor Red
                }
                Write-Host "Successfully assigned service principal to role: $RoleName" -foregroundcolor Green
            }
        } catch {
            Write-Host "Failed to assign Service Principal to directory roles: $_.Exception.Message" -foregroundcolor Red
            throw
        }
    }
    catch {
        Write-Host "Failed to create Application and Service Principal: $_.Exception.Message" -foregroundcolor Red
        throw
    }

    try{
        # Define Certificate settings
        $cert = New-SelfSignedCertificate -Subject "CN=$CertName" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256

        $base64Cert = [System.Convert]::ToBase64String($cert.RawData)

        # Define the Key Credentials Parameters
        $params = @{
            keyCredentials = @(
                @{
                    endDateTime = $cert.NotAfter
                    startDateTime = $cert.NotBefore
                    type = "AsymmetricX509Cert"
                    usage = "Verify"
                    key = [System.Convert]::FromBase64String($base64Cert)
                    displayName = "CN=$CertName"
                }
            )
        }

        Write-Host ""
        Write-Host "Successfully created certificate"
        Write-Host "Certficate expires on: $($cert.NotAfter)" -foregroundcolor Yellow
    } catch {
        Write-Host "Failed to create certificate: $_.Exception.Message" -foregroundcolor Red
    }

    try {
        #Update the application above with the certificate.
        Update-MgApplication -ApplicationId $app.Id -BodyParameter $params

        Write-Host "Successfully updated application with certificate" -foregroundcolor Green
    }
    catch {
        Write-Host "Failed to update application with certificate: $_.Exception.Message" -foregroundcolor Red
    }

    if($AddPowerAppsAccount){
        try {
            # https://github.com/cisagov/ScubaGear/blob/main/docs/prerequisites/noninteractive.md#power-platform

            $appId = $app.appId
            $TenantID = (Invoke-MgGraphRequest -Method GET -Uri "$GraphEndpoint/v1.0/organization").values[0].id

            # Login interactively with a tenant administrator for Power Platform
            $null = Add-PowerAppsAccount -Endpoint $PowerAppsEndpoint -TenantID $tenantId -WarningAction SilentlyContinue
            $PowerAppSetup = New-PowerAppManagementApp -ApplicationId $appId -WarningAction SilentlyContinue

            if ($PowerAppSetup) {
                Write-Host ""
                Write-Host "Power Platform setup was Successful!" -foregroundcolor Green
            } else {
                $null = Add-PowerAppsAccount -Endpoint $PowerAppsEndpoint -TenantID $tenantId -WarningAction SilentlyContinue
                $PowerAppSetup = New-PowerAppManagementApp -ApplicationId $appId -WarningAction SilentlyContinue

                if ($PowerAppSetup) {
                    Write-Host "Power Platform setup was Successful on retry!" -foregroundcolor Green
                } else {
                    Write-Host "Power Platform setup Failed on retry!" -foregroundcolor Red
                    throw
                }
            }
        } catch {
            Write-Host "Failed to perform Power Platform requirements: $_.Exception.Message" -foregroundcolor Red
            throw
        }
    }
}catch{
    Write-Host "Failed to create ScubaGear Application: $_.Exception.Message" -foregroundcolor Red
}finally{
    # Always disconnect from the graph
    $DisconnectGraph = Disconnect-MgGraph
    }
}

# Create a function that will update the service principal, I.e. create a new certificate and update the service principal with the new certificate
function Update-ScubaGearApp {
    <#
    .SYNOPSIS
        Add new certificate to the service principal.

    .DESCRIPTION
        This will add a new certificate to the service principal.

    .PARAMETER CertName
        Used to define your certificate name that will be stored on your device and used to interface with the ScubaGear application created in this script. The default is "ScubaGearCert"

    .PARAMETER ServicePrincipalName
        Used to define the name of the Service Principal that will be created.

    .EXAMPLE
        Update-ScubaGearApp -CertName "NameOfYourCert" -ServicePrincipalName "MyServicePrincipal"

        Add a new certificate named "NameOfYourCert" to the service principal with the name "MyServicePrincipal"

    .EXAMPLE
        Update-ScubaGearApp -ServicePrincipalName "MyServicePrincipal"

        Add a new certificate to the service principal with the name "MyServicePrincipal"

    .NOTES
        Author         : ScubaGear Team
        Prerequisite   : PowerShell 5.1 or later
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName = "NewCert")]
        [string]$CertName = "ScubaGearCert",

        [Parameter(Mandatory=$true)]
        [string]$AppID,

        [Parameter(Mandatory=$false, ParameterSetName = "NewCert")]
        [switch]$NewCert,

        [switch]$ListCerts,

        [string]$DeleteCert,

        [Parameter(Mandatory=$true)]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $True)]
        [string]$Environment
    )

    switch ($Environment.ToLower().Trim()) {
        "commercial" {
            $GraphEnvironment  = "Global"
        }
        "gcc" {
            $GraphEnvironment  = "Global"
        }
        "gcchigh" {
            $GraphEnvironment  = "USGov"
        }
        "dod" {
            $GraphEnvironment  = "USGovDoD"
        }
    }

    Try {
        # Connect to Microsoft Graph
        try {
            $Null = Connect-MgGraph -Scopes "Application.ReadWrite.All" -Environment $GraphEnvironment
            Write-Host "Successfully connected to Microsoft Graph"
        }
        catch {
            Write-Host "Failed to connect to Microsoft Graph: $_.Exception.Message"
        }

        if ($NewCert) {
            # Find the application object ID for "ScubaGear Application"
            $app1 = Get-MgApplication -Filter "appid eq '$AppID'"

            if ($app1) {
                # Create the new certificate
                $cert = New-SelfSignedCertificate -Subject "CN=$CertName" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
                $base64Cert = [System.Convert]::ToBase64String($cert.RawData)
                # Get existing key credentials
                $existingKeyCredentials = $app1.keyCredentials

                # Append the new certificate to the existing key credentials
                $newKeyCredential = @{
                    endDateTime = $cert.NotAfter
                    startDateTime = $cert.NotBefore
                    type = "AsymmetricX509Cert"
                    usage = "Verify"
                    key = [System.Convert]::FromBase64String($base64Cert)
                    displayName = "CN=$CertName"
                }

                # Ensure existing key credentials are not overwritten and add the new certificate to the list
                if ($existingKeyCredentials) {
                    $updatedKeyCredentials = $existingKeyCredentials + $newKeyCredential
                } else {
                    $updatedKeyCredentials = @($newKeyCredential)
                }

                # Update the application with the new key credentials
                $params = @{
                    keyCredentials = $updatedKeyCredentials
                }
                Update-MgApplication -ApplicationId $app1.Id -BodyParameter $params

                Write-host
                Write-Host "Certificate appended for application $($app1.DisplayName)" -ForegroundColor Blue
                Write-Host "Certificate Thumbprint - Utilize when running non-interactive: $($cert.Thumbprint)" -ForegroundColor Blue
            } else {
                Write-Host "Application ($ServicePrincipalName) not found" -ForegroundColor Red
            }
        } elseif ($ListCerts) {
            # Find the application object ID for "ScubaGear Application"
            $app1 = Get-MgApplication -Filter "appid eq '$AppID'"
            if ($app1) {
                # List current certificates
                Write-Host ""
                Write-Host "Current certificates for application $($app1.DisplayName):" -ForegroundColor Blue
                foreach ($cert in $app1.keyCredentials) {
                    Write-Host "Display Name: $($cert.displayName), Start Date: $($cert.startDateTime), End Date: $($cert.endDateTime)" -ForegroundColor Green
                }
            } else {
                Write-Host "Application ID: $AppID not found" -ForegroundColor Red
            }
        } elseif ($DeleteCert) {
            # Find the application object ID for "ScubaGear Application"
            $app1 = Get-MgApplication -Filter "appid eq '$AppID'"

            if ($app1) {
                # Get existing key credentials
                $existingKeyCredentials = $app1.keyCredentials

                # Convert to a resizable collection
                $resizableKeyCredentials = [System.Collections.ArrayList]@($existingKeyCredentials)

                # Find the key credential to remove
                $keyToRemove = $resizableKeyCredentials | Where-Object { $_.displayName -eq $DeleteCert }

                if ($keyToRemove) {
                    # Remove the specified key credential
                    $resizableKeyCredentials.Remove($keyToRemove)

                    # Update the application with the remaining key credentials
                    $params = @{
                        keyCredentials = $resizableKeyCredentials
                    }
                    Update-MgApplication -ApplicationId $app1.Id -BodyParameter $params
                    Write-Host "Certificate '$DeleteCert' removed from application $($app1.DisplayName)" -ForegroundColor Blue
                } else {
                    Write-Host "Certificate '$DeleteCert' not found in application $($app1.DisplayName)" -ForegroundColor Red
                }
            } else {
                Write-Host "Application with display name '$ServicePrincipalName' not found" -ForegroundColor Red
            }
        }
    } Catch {
        Write-Host "Failed to update service principal: $_.Exception.Message"
    }
}

Export-ModuleMember -Function New-ScubaGearServicePrincipal, Update-ScubaGearApp, Get-ScubaGearAppPermissions, Get-ScubaGearAppRoleIDs, Set-ScubaGearAPIPermissions, Set-ScubaGearRoles, Compare-ScubaGearPermissions