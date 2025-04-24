# Disable Activity History
# This script erases recent docs, clipboard, and run history by modifying registry keys.

# Function to set a registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Type,
        [string]$Value
    )

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        # Handle DWord type explicitly
        if ($Type -eq "DWord") {
            Set-ItemProperty -Path $Path -Name $Name -Value ([int]$Value) -Force
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
        }

        Write-Host "Set $Name to $Value in $Path" -ForegroundColor Green
    } catch {
        Write-Host "Error setting $Name in $Path $_" -ForegroundColor Red
    }
}

# Registry modifications
$registryChanges = @(
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        Name = "EnableActivityFeed"
        Type = "DWord"
        Value = "0"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        Name = "PublishUserActivities"
        Type = "DWord"
        Value = "0"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        Name = "UploadUserActivities"
        Type = "DWord"
        Value = "0"
    }
)

# Apply registry changes
foreach ($change in $registryChanges) {
    Set-RegistryValue -Path $change.Path -Name $change.Name -Type $change.Type -Value $change.Value
}

Write-Host "Activity history has been disabled." -ForegroundColor Cyan