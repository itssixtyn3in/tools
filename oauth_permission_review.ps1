# Define a mapping of dangerous permission IDs to human-readable names
$permissionMappings = @{
    "024d486e-b451-40bb-833d-3e66d98c5c73" = "Read and write access to user's email";
    "570282fd-fa5c-430d-a7fd-fc8dc98a9dca" = "Read the users email";
    "7b9103a5-4610-446b-9670-80643382c1fa" = "Read user and shared email";
    "a4b8392a-d8d1-4954-a029-8e668a39a170" = "Read users basic mail";
    "b11fa0e7-fdb7-4dc9-b1f1-59facd463480" = "Read users and basic shared mail";
    "5df07973-7d5d-46ed-9847-1271055cbd51" = "Read and write user and shared mail";
    "e383f46e-2787-4529-855e-0e479a3ffac0" = "Send Mail as the User";
    "a367ab51-6b49-43bf-a716-a1fb06d2a174" = "Send Mail on behalf of others";
    "ff74d97f-43af-4b68-9f2a-b77ee6968c5d" = "Read user contacts";
    "242b9d9e-ed24-4d09-9a52-f43769beb9d4" = "Read user and shared contacts";
    "d56682ec-c09e-4743-aaf4-1a3aac4caa21" = "Have full access to user contacts";
    "afb6c84b-06be-49af-80bb-8f3f77004eab" = "Read and write user and shared contacts";
    "87f447af-9fa4-4c32-9dfa-4a57a73d18ce" = "Read user's mailbox settings";
    "818c620a-27a9-40bd-a6a5-d96f7d610b4b" = "Read and write access to user's mailbox settings";
    "ba47897c-39ec-4d83-8086-ee8256fa737d" = "Read user's people data";
    "b89f9189-71a5-4e70-b041-9887f0bc7e4a" = "Read all users' relevant people lists";
    "10465720-29dd-4523-a11a-6a75c743c9d9" = "Read User Files";
    "df85f4d6-205c-4ac5-a5ea-6bf408dba283" = "Read all files that user can access";
    "5447fe39-cb82-4c1a-b977-520e67e724eb" = "Read files that the user selects (preview)";
    "5c28f0bf-8a70-41f1-8ab2-9032436ddb65" = "Have full access to user files";
    "863451e7-0667-486c-a5d6-d135439485f0" = "Have full access to all files user can access";
    "8019c312-3263-48e6-825e-2b833497195b" = "Have full access to the application's folder (preview)";
    "17dde5bd-8c17-420f-a486-969730c1b827" = "Read and write files that the user selects (preview)";
    "9d822255-d64d-4b7a-afdb-833b9a97ed02" = "Create user OneNote notebooks";
    "371361e4-b9e2-4a3f-8315-2a301a3b0a3d" = "Read user OneNote notebooks";
    "dfabfca6-ee36-4db2-8208-7a28381419b3" = "Read all OneNote notebooks that user can access";
    "615e26af-c38a-4150-ae3e-c3b0d4cb1d6a" = "Read and write user OneNote notebooks";
    "64ac0503-b4fa-45d9-b544-71a463f05da0" = "Read and write all OneNote notebooks that user can access";
    "0e263e50-5827-48a4-b97c-d940288653c7" = "Access directory as the signed-in user";
    # Add more potentially malicious permissions as needed
}

# Define a mapping of application names to skip
$appNameSkipList = @("SecurityVerification", "VerificationGateway")

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

    # Check if RequiredResourceAccess property is available
    if ($app.RequiredResourceAccess) {
        foreach ($resourceAccess in $app.RequiredResourceAccess) {
            # Output the regular permissions found
            Write-Host "`tApp Registration Name: $($app.DisplayName)"
            Write-Host "`tPermissions:" -NoNewline

            $firstPermission = $true
            foreach ($permission in $resourceAccess.ResourceAccess) {
                # Get human-readable permission name from the mapping
                $permissionName = $permissionMappings[$permission.Id]
                if ($permissionName) {
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
