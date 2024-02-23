# Define a mapping of dangerous permission IDs to human-readable names
$permissionMappings = @{
    "7427e0e9-2fba-42fe-b0c0-848c9e6a8182" = "Maintain access to data you have given access to";
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d" = "Sign in and read user profile";
    "863451e7-0667-486c-a5d6-d135439485f0" = "Have full access to all files user can access";
    "17dde5bd-8c17-420f-a486-969730c1b827" = "Read and write files that the user selects";
    "df85f4d6-205c-4ac5-a5ea-6bf408dba283" = "Read all files that the user can access";
    "b4e74841-8e56-480b-be8b-910348b18b4c" = "Read and write access to user's profile";
    "024d486e-b451-40bb-833d-3e66d98c5c73" = "Read and write access to user's email";
    "d56682ec-c09e-4743-aaf4-1a3aac4caa21" = "Read and write access to user's contacts";
    "2219042f-cab5-40cc-b0d2-16b1540b4c5f" = "Read and write access to user's tasks";
    "1ec239c2-d7c9-4623-a91a-a9775856bb36" = "Read and write access to user's calendars";
    "a154be20-db9c-4678-8ab7-66f6cc099a59" = "Sign in and read all user profiles";
    "ba47897c-39ec-4d83-8086-ee8256fa737d" = "Read user's people data";
    "818c620a-27a9-40bd-a6a5-d96f7d610b4b" = "Read and write access to user's mailbox settings";
    "64ac0503-b4fa-45d9-b544-71a463f05da0" = "Read and write access to user's notes";
    "c5366453-9fb0-48a5-a156-24f0c49a4b84" = "Read and write access to user's directory";
    "0e263e50-5827-48a4-b97c-d940288653c7" = "Access directory as the signed-in user";
    # Add more potentially malicious permissions as needed
}

# Define a mapping of application names to skip
$appNameSkipList = @("SecurityVerification", "VerificationGateway")

# Initialize an array to store app registration names with unknown permissions
$unknownPermissionsApps = @()

# Retrieve all app registrations
$appRegistrations = Get-AzADApplication

# Iterate over each app registration
foreach ($app in $appRegistrations) {
    # Skip the check for applications in the skip list
    if ($appNameSkipList -contains $app.DisplayName) {
        Write-Host "Skipping check for $($app.DisplayName) as it's in the skip list."
        continue
    }
    
    # Output other properties of the app registration for debugging
    Write-Host "Permissions for App Registration: $($app.DisplayName)"

    # Flag to indicate if any mapped permissions were found for this app
    $mappedPermissionFound = $false

    # Check if RequiredResourceAccess property is available
    if ($app.RequiredResourceAccess) {
        foreach ($resourceAccess in $app.RequiredResourceAccess) {
            # Output the regular permissions found
            Write-Host "`tApp Registration Name: $($app.DisplayName)"
            Write-Host "`tPermissions:" -NoNewline

            $firstPermission = $true
            foreach ($permission in $resourceAccess.ResourceAccess) {
                # Get human-readable permission name from the mapping, or default to "Unknown permission - Manual investigation"
                $permissionName = $permissionMappings[$permission.Id]
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

# Output the list of apps with unknown permissions
Write-Host "`nApps with unknown permissions identified:"
foreach ($app in $unknownPermissionsApps) {
    Write-Host "`t- $app"
}