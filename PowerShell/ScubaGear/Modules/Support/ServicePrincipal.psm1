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

    .PARAMETER Roles
        The roles that are required for the ScubaGear application.

    .PARAMETER ExtraPermissions
        Used to define whether the function will return extra permissions that are not in the AppRoleIDs array. This is a switch parameter and not ran by default.

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
        [string[]]$Roles,

        [Parameter(Mandatory = $false)]
        [switch]$ExtraPermissions
    )

    if($Roles){
        # Assign the service principal to the directory roles
        $SPRoleAssignment = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$ServicePrincipalID'"
        if($Null -ne $SPRoleAssignment){
            $ISGRRole = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $SPRoleAssignment.roleDefinitionId
        }

        if($Roles -notcontains $ISGRRole.DisplayName){
            ForEach ($Role in $Roles) {
                $RoleName = $Role
                $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'"
            }
            Write-Output "Service Pricipal missing role: $Roles"
            Write-Output ""
        }else{
            Write-Output ""
            Write-Output "Service Principal already assigned to directory roles [$Roles] as specified in the permissions file."
        }
        return $roleDefinition.Id
    }else{
        $SPMissingPerms = @()
        $ExtraPerms = @()

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

            if (-not $PSBoundParameters.ContainsKey('ExtraPermissions')) {
                # Output the updated $SPMissingPerms
                $missingPermsCount = $SPMissingPerms.leastPermissions.Count

                if($missingPermsCount -eq 0){
                    Write-Output "Service Principal permissions comparison completed, no API permissions missing."
                }else{
                    Write-Warning "Service Principal permissions comparison completed, missing [$missingPermsCount] API permissions"

                    # Output the missing permissions
                    ForEach ($MissingPerm in $SPMissingPerms) {
                        Write-Output ""
                        Write-Output "Missing API Permission: $($MissingPerm.leastPermissions)"
                    }
                }
            }

            # Determine if the service principal has any extra permissions
            $SPExtraPerms = $Diff | Where-Object {$_.SideIndicator -eq "=>"}

            if($PSBoundParameters.ContainsKey('ExtraPermissions') -and $SPExtraPerms){
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
                    <#
                    # Output the results
                    If ($APIPermissionName) {
                        Write-Warning "Extra API Permission: $APIPermissionName"
                    } Else {
                        Write-Warning "No matching API permission found for ID: $($ExtraPerm).InputObject"
                    }
                    #>

                    # Add to ExtraPerms array
                    $ExtraPerms += "Extra API Permission: $APIPermissionName"
                }
            }
        } else {
            Write-Output "No service principal permissions found, skipping comparison."
        }

        # Return the appropriate value based on the switch
        if ($ExtraPermissions) {
            Write-Output ""
            return $ExtraPerms
        } else {
            return $SPMissingPerms
        }
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
        $Null = New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $ServicePrincipalId -RoleDefinitionId $roleDefinitionId -DirectoryScopeId "/"
        $RoleName = (Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $roleDefinitionID).DisplayName
        Write-Output "Assigned service principal to role: $RoleName"
    } catch {
        Write-Warning "Failed to assign service principal to role: $RoleName"
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
            Write-Warning "Failed to retrieve $ProductName API Permission: $APIPermissionNames : $_.Exception.Message"
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
        [object]$SPMissingPerms,

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
                    Write-Output "Assigned $ProductName API Permission: $($MissingPerm.leastPermissions)"
                } catch {
                    Write-Warning "Failed to assign missing $ProductName API Permission: $APIPermissionName : $_.Exception.Message"
                }
            }
        } catch {
            Write-Warning "Failed to assign Service Principal to API permissions: $_.Exception.Message"
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
                Write-Output "Assigned $ProductName API Permission: $APIPermissionName"
            }
        } catch {
            Write-Warning"Failed to assign Service Principal to API permissions: $_.Exception.Message"
            throw
        }
    } else {
        Write-Output "Service Principal already assigned to API permissions, skipping assignment."
    }
}

Function Remove-AllAPIPermissions {
    <#

    .SYNOPSIS
        Removes all API permissions from the service principal.

    .DESCRIPTION
        This function will remove all API permissions from the service principal.

    .PARAMETER AppID
        Used to define the AppID of the service principal that will be removed from all API permissions.

    .PARAMETER Environment
        Used to define the environment that the application will be created in. The options are commercial, gcc, gcchigh, dod

    .EXAMPLE
        Remove-AllAPIPermissions -AppID "AppID" -Environment commercial

        This example will remove all API permissions from the service principal with the specified AppID.

    .NOTES
        Author         : ScubaGear Team
        Prerequisite   : PowerShell 5.1 or later
    #>

        param(
            [Parameter(Mandatory = $true)]
            [string]$AppID,

            [Parameter(Mandatory = $true)]
            [string]$ServicePrincipalID,

            [Parameter(Mandatory = $true)]
            [array]$ScubaGearSPPermissions,

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
            Write-Verbose "Successfully connected to Microsoft Graph"
        }
        catch {
            Write-Warning "Failed to connect to Microsoft Graph: $_.Exception.Message"
        }

        try{
            # Retrieve the permissions from existing service principal
            $app = Get-MgApplication -Filter "appId eq '$appId'"

            # Remove API permissions by updating the app registration
            $app.RequiredResourceAccess.Clear()  # This clears all the required resource access entries
            Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $app.RequiredResourceAccess

            $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalId
            foreach ($assignment in $appRoleAssignments) {
                Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalId -AppRoleAssignmentId $assignment.Id -Confirm:$false
            }
        }catch {
            Write-Warning "Failed to remove API permissions from the service principal: $_.Exception.Message"
            throw
        }

        # Assign the permissions to the service principal
        try {
            $Null = Set-ScubaGearAPIPermissions -ServicePrincipalID $ServicePrincipalID -ScubaGearSPPermissions $ScubaGearSPPermissions
            Write-Output "Assigned API permissions to the service principal: $($ScubaGearSPPermissions)"
        }
        catch {
            Write-Warning "Failed to assign API permissions: $_.Exception.Message"
            throw
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
        Write-Verbose "Successfully connected to Microsoft Graph"
    }
    catch {
        Write-Warning "Failed to connect to Microsoft Graph: $_.Exception.Message"
    }

    # Required Permissions for the ScubaGear Application
    $ScubaGearSPPermissions = Get-ScubaGearEntraRedundantPermissions -ServicePrincipal | Sort-Object -Property LeastPermissions,resourceAPiAppID -Unique

    # Required Roles for the ScubaGear Application
    $ScubaGearSPRole = Get-ScubaGearPermissions -OutAs role

    # Retrieve the permissions from existing service principal
    $SP = Get-MgServicePrincipal -filter "appId eq '$AppID'"
    $SPPerms = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id

    # Create an object to store the permissions
    $AppRoleIDs = Get-ScubaGearAppRoleIDs -ScubaGearSPPermissions $ScubaGearSPPermissions

    # Compare the service principal permissions against the AppRoleIDs array
    $SPMissingPerms = Compare-ScubaGearPermissions -ServicePrincipalID $SP.ID -AppRoleIDs $AppRoleIDs
    $SPMissingPerms

    # Check if the service principal has any extra permissions that are not in the ScubaGearSPPermissions
    $SPExtraPerms = Compare-ScubaGearPermissions -ServicePrincipalID $SP.ID -AppRoleIDs $AppRoleIDs -ExtraPermissions
    $SPExtraPerms

    # Compare the service principal to the directory roles
    $SPRoleAssignment = Compare-ScubaGearPermissions -ServicePrincipalID $SP.ID -Roles $ScubaGearSPRole
    $SPRoleAssignment

    # If there are differences, assign the service principal to the API permissions if the -FixPermissionIssues switch is used
    if($PSBoundParameters.ContainsKey('FixPermissionIssues') -and ($null -ne $SPMissingPerms -and $SPMissingPerms -match "Missing API Permission") -and $Null -eq $SPExtraPerms){
        # Assign the missing permissions to the service principal
        Write-Output "Service Principal permissions comparison completed, missing [$($SPMissingPerms.leastPermissions.Count)] API permissions"
        $Null = Set-ScubaGearAPIPermissions -ServicePrincipalID $SP.ID -SPMissingPerms $SPMissingPerms -ScubaGearSPPermissions $ScubaGearSPPermissions -SPPerms $SPPerms

    }elseif($PSBoundParameters.ContainsKey('FixPermissionIssues') -and (($Null -eq $SPPerms) -or $SPRoleAssignment)){
        if($Null -eq $SPPerms){
            # Assign the service principal to the required permissions
            Write-Output "Assigning service principal to API permissions as specified in the permissions file."
            $Null = Set-ScubaGearAPIPermissions -ServicePrincipalID $SP.ID -ScubaGearSPPermissions $ScubaGearSPPermissions
        }elseif($SPRoleAssignment[1] -notmatch "Service Principal already assigned to directory roles"){
            # Assign the service principal to the required roles
            Write-Output "Assigning service principal to directory roles [$ScubaGearSPRole] as specified in the permissions file."
            $Null = Set-ScubaGearRoles -ServicePrincipalID $SP.ID -roleDefinitionID $SPRoleAssignment
        }elseif($PSBoundParameters.ContainsKey('FixPermissionIssues') -and $SPExtraPerms -match "Extra API Permission:"){
            # Remove the extra permissions from the service principal
            Write-Output "Removing extra API permissions from the service principal"
            $Null = Remove-AllAPIPermissions -AppID $AppID -ServicePrincipalID $SP.ID -ScubaGearSPPermissions $ScubaGearSPPermissions -Environment $Environment
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
        $Null = Connect-MgGraph -Scopes "Application.ReadWrite.All, RoleManagement.ReadWrite.Directory" -Environment $GraphEnvironment -NoWelcome
        Write-Verbose "Successfully connected to Microsoft Graph"
    }
    catch {
        Write-Warning "Failed to connect to Microsoft Graph: $_.Exception.Message"
    }

    # Required Permissions for the ScubaGear Application
    $requiredResourcePermissions = Get-ScubaGearEntraRedundantPermissions -ServicePrincipal | Sort-Object -Property LeastPermissions,resourceAPiAppID -Unique

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
        Write-Verbose "Service Principal Application (Client) ID: $($app.Id)"

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
                Write-Verbose "Assigned $ProductName API Permission: $APIPermissionName"
            }
        }catch {
            Write-Warning "Failed to assign Service Principal to API permissions: $_.Exception.Message"
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
                    Write-Warning "Failed to assign service principal to role: $RoleName"
                }
                Write-Verbose "Successfully assigned service principal to role: $RoleName"
            }
        } catch {
            Write-Warning "Failed to assign Service Principal to directory roles: $_.Exception.Message"
            throw
        }
    }
    catch {
        Write-Warning "Failed to create Application and Service Principal: $_.Exception.Message"
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

        Write-Verbose "Successfully created certificate"
        Write-Verbose "Certficate expires on: $($cert.NotAfter)"
    } catch {
        Write-Warning "Failed to create certificate: $_.Exception.Message"
    }

    try {
        #Update the application above with the certificate.
        Update-MgApplication -ApplicationId $app.Id -BodyParameter $params

        Write-Output "Successfully updated application with certificate"
    }
    catch {
        Write-Warning "Failed to update application with certificate: $_.Exception.Message"
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
                Write-Output "Power Platform setup was Successful!"
            } else {
                $null = Add-PowerAppsAccount -Endpoint $PowerAppsEndpoint -TenantID $tenantId -WarningAction SilentlyContinue
                $PowerAppSetup = New-PowerAppManagementApp -ApplicationId $appId -WarningAction SilentlyContinue

                if ($PowerAppSetup) {
                    Write-Output "Power Platform setup was Successful on retry!"
                } else {
                    Write-Warning "Power Platform setup Failed on retry! $_.Exception.Message"
                    throw
                }
            }
        } catch {
            Write-Warning "Failed to perform Power Platform requirements: $_.Exception.Message"
            throw
        }
    }
}catch{
    Write-Warning "Failed to create ScubaGear Application: $_.Exception.Message"
}finally{
    # Always disconnect from the graph
    $Null = Disconnect-MgGraph
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
        Used to define your certificate name that will be stored on your device and used to interface with the ScubaGear application created in this script.

    .PARAMETER ServicePrincipalName
        Used to define the name of the Service Principal that will be created.

    .PARAMETER AppID
        Used to define the AppID of the service principal that will be updated.

    .PARAMETER Environment
        Used to define the environment that the application will be created in. The options are commercial, gcc, gcchigh, dod

    .PARAMETER ListCerts
        List the current certificates for the service principal.

    .PARAMETER DeleteCert
        Delete the certificate from the service principal.

    .PARAMETER NewCert
        Add a new certificate to the service principal.

    .EXAMPLE
        Update-ScubaGearApp -NewCert -CertName "NameOfYourCert" -ServicePrincipalName "MyServicePrincipal" -environment "gcchigh" -appId "AppID"

        Add a new certificate named "NameOfYourCert" to the service principal with the name "MyServicePrincipal"

    .EXAMPLE
        Update-ScubaGearApp -ServicePrincipalName "MyServicePrincipal" -Environment "commercial" -ListCerts -appId "AppID"

        List the current certificates for the service principal with the name "MyServicePrincipal"

    .EXAMPLE
        Update-ScubaGearApp -ServicePrincipalName "MyServicePrincipal" -Environment "dod" -DeleteCert "CN=NameOfYourCert" -appId "AppID"

        Delete the certificate named "CN=NameOfYourCert" from the service principal with the name "MyServicePrincipal"

    .NOTES
        Author         : ScubaGear Team
        Prerequisite   : PowerShell 5.1 or later
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName = "NewCert")]
        [string]$CertName,

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
            $Null = Connect-MgGraph -Scopes "Application.ReadWrite.All" -Environment $GraphEnvironment -NoWelcome
            Write-Verbose "Successfully connected to Microsoft Graph"
        }
        catch {
            Write-Warning "Failed to connect to Microsoft Graph: $_.Exception.Message"
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

                Write-Output ""
                Write-Output "Certificate appended for application $($app1.DisplayName)"
                Write-Output ""
                Write-Output "Certificate details utilized when running non-interactive:"
                Write-Output "Certificate Thumbprint: $($cert.Thumbprint)"
                Write-Output "SP Client/App ID: $($app1.AppId)"
                Write-Output "Organization: $($app1.PublisherDomain)"
            } else {
                Write-Warning "Application ($ServicePrincipalName) not found"
            }
        } elseif ($ListCerts) {
            # Find the application object ID for "ScubaGear Application"
            $app1 = Get-MgApplication -Filter "appid eq '$AppID'"
            if ($app1) {
                # List current certificates
                Write-Output ""
                Write-Output "Current certificates for application $($app1.DisplayName):"
                foreach ($cert in $app1.keyCredentials) {
                    Write-Output "Display Name: $($cert.displayName)"
                    Write-Output "Start Date  : $($cert.startDateTime)"
                    Write-Output "End Date    : $($cert.endDateTime)"
                    Write-Output ""
                }
            } else {
                Write-Warning "Application ID: $AppID not found"
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
                    ForEach ($key in $keyToRemove) {
                        $resizableKeyCredentials.Remove($key)
                    }

                    # Update the application with the remaining key credentials
                    $params = @{
                        keyCredentials = $resizableKeyCredentials
                    }
                    Update-MgApplication -ApplicationId $app1.Id -BodyParameter $params
                    Write-Output "Certificate '$DeleteCert' removed from application $($app1.DisplayName)"
                } else {
                    Write-Warning "Certificate '$DeleteCert' not found in application $($app1.DisplayName)"
                }
            } else {
                Write-Warning "Application with display name '$ServicePrincipalName' not found"
            }
        }
    } Catch {
        Write-Warning "Failed to update service principal: $_.Exception.Message"
    }
}

Export-ModuleMember -Function New-ScubaGearServicePrincipal, Update-ScubaGearApp, Get-ScubaGearAppPermissions, Get-ScubaGearAppRoleIDs, Set-ScubaGearAPIPermissions, Set-ScubaGearRoles, Compare-ScubaGearPermissions, Remove-AllAPIPermissions