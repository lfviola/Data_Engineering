
# Authenticate to Microsoft Graph and Azure
Connect-AzAccount -Identity
Connect-MgGraph -Identity -Scopes "Group.Read.All", "User.Read.All"

# Get Databricks workspace details
$workspaceName = "your-databricks-workspace-name"
$resourceGroup = "your-resource-group"
$subscriptionId = "your-subscription-id"

$workspace = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" `
                             -ResourceGroupName $resourceGroup `
                             -ResourceName $workspaceName

$databricksUrl = "https://" + $workspace.Properties.workspaceUrl

# Get AAD access token for Databricks API
$token = Get-AzAccessToken -ResourceUrl "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d" `
                           -ResourceId $workspace.Id
$headers = @{
    Authorization = "Bearer $($token.Token)"
    'Content-Type' = 'application/scim+json'
}

# Get group ID from group name
$groupName = "PAG-dqe-p"
$group = Get-MgGroup -Filter "displayName eq '$groupName'" -ConsistencyLevel eventual
$groupId = $group.Id

# Load previous members from Automation Variable
try {
    $previousRaw = Get-AutomationVariable -Name "previous_members"
    $previousMembers = $previousRaw -split ","
} catch {
    $previousMembers = @()
}

# Get current group members
$currentMembers = Get-MgGroupMember -GroupId $groupId -All |
    Where-Object { $_.UserPrincipalName } |
    ForEach-Object { $_.UserPrincipalName }

# Compute delta
$addedMembers = $currentMembers | Where-Object { $_ -notin $previousMembers }
$removedMembers = $previousMembers | Where-Object { $_ -notin $currentMembers }

# Add users to Databricks
foreach ($user in $addedMembers) {
    Write-Output "Adding user to Databricks: $user"

    $body = @{
        userName = $user
        emails   = @(@{ value = $user })
        entitlements = @(@{ value = "allow-cluster-create" })
    } | ConvertTo-Json -Depth 3

    try {
        Invoke-RestMethod -Uri "$databricksUrl/api/2.0/preview/scim/v2/Users" -Method Post -Headers $headers -Body $body
        Write-Output "✅ Added $user"
    } catch {
        Write-Output "⚠️ Could not add $user: $_"
    }
}

# Optional: handle removals
foreach ($user in $removedMembers) {
    Write-Output "⚠️ User $user removed from group – manual cleanup needed"
}

# Save current members
$newRaw = ($currentMembers -join ",")
Set-AutomationVariable -Name "previous_members" -Value $newRaw
