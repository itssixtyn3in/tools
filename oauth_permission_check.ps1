# Define a mapping of dangerous permission IDs to human-readable names
$permissionMappings = @{
    "7427e0e9-2fba-42fe-b0c0-848c9e6a8182" = "Read user data";
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d" = "Access user data offline";
    "a154be20-db9c-4678-8ab7-66f4df5d6abc" = "Have full access to all files user can access";
    "10d3f197-7a34-4420-b3b6-0e6f68d52db5" = "Read and write files that the user selects";
    "b743dd9d-672d-4850-8363-60fd6fb23a64" = "Read and write all files that the user can access";
    # Add more potentially malicious permissions as needed
}

# Define a mapping of regular permission IDs to human-readable names
$regularPermissionMappings = @{
    "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0" = "Read and write access to user's organization data";
    "311a71cc-e848-46a1-bdf8-97ff7156d8e6" = "Read items in all site collections";
    "c4e39a17-377d-4ee1-ba05-1a8e12620c38" = "Read and write items in all site collections";
    "2d4154c1-8b39-48b6-8318-9e0afb621b93" = "Read and write access to user mail";
    "68ccd8d2-785a-4f9c-9ef4-589aae5bd99d" = "Read and write access to user calendars";
    "b03eb5e9-8316-496e-8a03-4d7f1fe7b339" = "Read and write access to user calendars";
    "5dc5f032-145f-4d3f-8fc9-9101192c2d0b" = "Read and write access to user files";
    "9f06204d-3d71-4d33-8e6c-4e376723b94f" = "Read and write access to user files";
    "037d6b68-4a97-41d3-b5e5-e1b35be6d542" = "Read items in all site collections";
    "5f201a7e-8445-4a86-9f76-7f8594e74801" = "Read and write access to user mail";
    # Add more permissions as needed
}

# Remove dangerous permissions from regular permissions mapping to avoid duplicates
foreach ($permissionId in $permissionMappings.Keys) {
    $regularPermissionMappings.Remove($permissionId)
}

# Combine the dangerous permissions with regular permissions to build a complete list of permissions
$allPermissions = @{}
foreach ($key in $permissionMappings.Keys) {
    $allPermissions[$key] = $permissionMappings[$key]
}
foreach ($key in $regularPermissionMappings.Keys) {
    $allPermissions[$key] = $regularPermissionMappings[$key]
}

# Initialize a counter for total app registrations processed
$totalAppsProcessed = 0

# Initialize an array to store app registration names with unknown permissions
$unknownPermissionsApps = @()

# Retrieve all app registrations
$appRegistrations = Get-AzADApplication

# Iterate over each app registration
foreach ($app in $appRegistrations) {
    # Increment the counter for total app registrations processed
    $totalAppsProcessed++

    # Flag to indicate if any mapped permissions were found for this app
    $mappedPermissionFound = $false

    # Output other properties of the app registration for debugging
    Write-Host "Permissions for App Registration: $($app.DisplayName)"

    # Check if RequiredResourceAccess property is available
    if ($app.RequiredResourceAccess) {
        foreach ($resourceAccess in $app.RequiredResourceAccess) {
            # Output the regular permissions found
            Write-Host "`tApp Registration Name: $($app.DisplayName)"
            Write-Host "`tPermissions:" -NoNewline

            $firstPermission = $true
            foreach ($permission in $resourceAccess.ResourceAccess) {
                # Get human-readable permission name from the mapping, or default to "Unknown permission - Manual investigation"
                $permissionName = $allPermissions[$permission.Id]
                if (-not $permissionName) {
                    $permissionName = "Unknown permission - Manual investigation"
                    $unknownPermissionsApps += $app.DisplayName
                }
                if ($permissionName) {
                    $mappedPermissionFound = $true
                    if (-not $firstPermission) {
                        Write-Host -NoNewline ", "
                    }
                    Write-Host -NoNewline " $permissionName" -ForegroundColor Red
                    $firstPermission = $false
                }
            }
            Write-Host
        }
    } else {
        Write-Host "`tNo required resource access found for this app registration."
    }

    Write-Host "------------------------------------------------"
}

# Output the count of apps found with potentially dangerous permissions
Write-Host "Total Apps Processed: $totalAppsProcessed"

# Output the list of apps with unknown permissions
Write-Host "`nApps with unknown permissions identified:"
foreach ($app in $unknownPermissionsApps) {
    Write-Host "`t- $app"
}