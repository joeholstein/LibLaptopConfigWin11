# Combined Windows Setup, Cleanup & Configuration Script
# Run as Administrator!

#region PREP
Write-Host "[STARTING SETUP SCRIPT...]" -ForegroundColor Cyan
$ErrorActionPreference = "Continue"
#endregion

#region APPLICATION REMOVAL
Write-Host "`n[SECTION 1] APPLICATION REMOVAL" -ForegroundColor Yellow

# --- Remove Specific Applications (MSI-based and via Registry Uninstall) ---
$specificAppsToRemove = @(
    "Lenovo Now",
    "Lenovo Smart Meeting Components",
    "Lenovo Vantage Service",
    "Microsoft 365",
    "WebAdvisor"
)

# 1.1 Remove via WMI/MSI-based installations
Write-Host "Removing applications via WMI/MSI..." -ForegroundColor White
foreach ($appName in $specificAppsToRemove) {
    Write-Host "Searching for $appName..." -ForegroundColor White
    $installedApps = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$appName*" }
    if ($installedApps) {
        foreach ($app in $installedApps) {
            Write-Host "Uninstalling $($app.Name)..." -ForegroundColor Yellow
            $result = $app.Uninstall()
            if ($result.ReturnValue -eq 0) {
                Write-Host "Successfully uninstalled $($app.Name)" -ForegroundColor Green
            } else {
                Write-Host "Failed to uninstall $($app.Name) with error code: $($result.ReturnValue)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No MSI installations found for $appName" -ForegroundColor Yellow
    }
}

# 1.2 Remove via Registry Uninstall Strings (non-MSI)
Write-Host "`nAttempting to remove applications via registry uninstall strings..." -ForegroundColor White
$uninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
foreach ($appName in $specificAppsToRemove) {
    Write-Host "Searching for $appName in registry..." -ForegroundColor White
    $foundApps = @()
    foreach ($key in $uninstallKeys) {
        $foundApps += Get-ItemProperty $key -ErrorAction SilentlyContinue |
                      Where-Object { $_.DisplayName -like "*$appName*" }
    }
    if ($foundApps.Count -gt 0) {
        foreach ($app in $foundApps) {
            if ($app.UninstallString) {
                Write-Host "Found $($app.DisplayName) - Attempting uninstall..." -ForegroundColor Yellow
                if ($app.UninstallString -like "*msiexec*") {
                    $uninstallCmd = $app.UninstallString -replace "msiexec.exe /i", "msiexec.exe /x"
                    $uninstallCmd = $uninstallCmd -replace "/I", "/X"
                    $uninstallCmd += " /qn /norestart"
                } else {
                    $uninstallCmd = $app.UninstallString
                    if ($uninstallCmd -like "*setup*" -or $uninstallCmd -like "*install*") {
                        $uninstallCmd += " /S /silent /quiet /uninstall /norestart"
                    }
                }
                try {
                    Start-Process cmd -ArgumentList "/c $uninstallCmd" -Wait -NoNewWindow
                    Write-Host "Uninstall command executed for $($app.DisplayName)" -ForegroundColor Green
                } catch {
                    Write-Host "Error running uninstall command for $($app.DisplayName): $_" -ForegroundColor Red
                }
            } else {
                Write-Host "No uninstall string found for $($app.DisplayName)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No registry entries found for $appName" -ForegroundColor Yellow
    }
}

# --- Remove UWP/AppX Packages for Modern Apps ---
Write-Host "`nAttempting to remove UWP/AppX packages..." -ForegroundColor White
$specificAppxPackages = @(
    "*LenovoNow*",
    "*LenovoSmartMeeting*",
    "*LenovoVantage*",
    "*Microsoft.Office*",
    "*Microsoft365*",
    "*WebAdvisor*"
)
foreach ($package in $specificAppxPackages) {
    Write-Host "Searching for AppX packages matching $package..." -ForegroundColor White
    $foundPackages = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $package }
    if ($foundPackages) {
        foreach ($foundPackage in $foundPackages) {
            Write-Host "Removing AppX package: $($foundPackage.Name)" -ForegroundColor Yellow
            try {
                Remove-AppxPackage -Package $foundPackage.PackageFullName -ErrorAction Stop
                Write-Host "Successfully removed AppX package: $($foundPackage.Name)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove AppX package $($foundPackage.Name): $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No AppX packages found matching $package" -ForegroundColor Yellow
    }
    
    # Remove provisioned packages to avoid reinstallation
    $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $package }
    if ($provisionedPackages) {
        foreach ($provPackage in $provisionedPackages) {
            Write-Host "Removing provisioned AppX package: $($provPackage.DisplayName)" -ForegroundColor Yellow
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $provPackage.PackageName -ErrorAction Stop
                Write-Host "Successfully removed provisioned package: $($provPackage.DisplayName)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove provisioned package $($provPackage.DisplayName): $_" -ForegroundColor Red
            }
        }
    }
}

# --- Additional Microsoft Store Bloatware Removal ---
Write-Host "`nRemoving Microsoft Store bloatware apps..." -ForegroundColor Yellow
$AppxBloatwareList = @(
    "Microsoft.3DBuilder",
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Office.OneNote",
    "Microsoft.People",
    "Microsoft.SkypeApp",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.MicrosoftNews",
    "Microsoft.WindowsFeedbackHub",
    "E0469640.LenovoSmartCommunication",
    "E046963F.LenovoCompanion"
)
foreach ($App in $AppxBloatwareList) {
    $Package = Get-AppxPackage -Name $App -AllUsers -ErrorAction SilentlyContinue
    if ($Package) {
        Write-Host "Removing $App for all users..." -ForegroundColor Yellow
        Remove-AppxPackage -Package $Package.PackageFullName -ErrorAction SilentlyContinue
    } else {
        Write-Host "$App not found for current user." -ForegroundColor Green
    }
}
foreach ($App in $AppxBloatwareList) {
    $ProvisionedApp = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $App }
    if ($ProvisionedApp) {
        Write-Host "Removing provisioned package: $App" -ForegroundColor Yellow
        Remove-AppxProvisionedPackage -Online -PackageName $ProvisionedApp.PackageName -ErrorAction SilentlyContinue
    } else {
        Write-Host "$App is not provisioned on this system." -ForegroundColor Green
    }
}

# --- Disable Lenovo-Specific Services, Scheduled Tasks & Cleanup Folders ---
Write-Host "`nDisabling Lenovo-specific services..." -ForegroundColor Yellow
$lenovoServices = @(
    "LenovoVantageService",
    "Lenovo*",
    "SmartMeeting*"
)
foreach ($service in $lenovoServices) {
    $foundServices = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($foundServices) {
        foreach ($foundService in $foundServices) {
            Write-Host "Stopping and disabling service: $($foundService.Name)" -ForegroundColor Yellow
            try {
                Stop-Service -Name $foundService.Name -Force -ErrorAction Stop
                Set-Service -Name $foundService.Name -StartupType Disabled -ErrorAction Stop
                Write-Host "Successfully disabled service: $($foundService.Name)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to stop/disable service $($foundService.Name): $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No services found matching $service" -ForegroundColor Yellow
    }
}

Write-Host "`nRemoving related scheduled tasks..." -ForegroundColor Yellow
$tasksToRemove = @(
    "*Lenovo*",
    "*WebAdvisor*"
)
foreach ($taskPattern in $tasksToRemove) {
    $foundTasks = Get-ScheduledTask -TaskName $taskPattern -ErrorAction SilentlyContinue
    if ($foundTasks) {
        foreach ($task in $foundTasks) {
            Write-Host "Removing scheduled task: $($task.TaskName)" -ForegroundColor Yellow
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
                Write-Host "Successfully removed scheduled task: $($task.TaskName)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove scheduled task $($task.TaskName): $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No scheduled tasks found matching $taskPattern" -ForegroundColor Yellow
    }
}

Write-Host "`nRemoving leftover application folders..." -ForegroundColor Yellow
$foldersToRemove = @(
    "$env:ProgramFiles\Lenovo\*Now*",
    "$env:ProgramFiles\Lenovo\*Vantage*",
    "$env:ProgramFiles\Lenovo\*Smart Meeting*",
    "$env:ProgramFiles (x86)\Lenovo\*Now*",
    "$env:ProgramFiles (x86)\Lenovo\*Vantage*",
    "$env:ProgramFiles (x86)\Lenovo\*Smart Meeting*",
    "$env:ProgramFiles\WebAdvisor",
    "$env:ProgramFiles (x86)\WebAdvisor"
)
foreach ($folder in $foldersToRemove) {
    if (Test-Path $folder) {
        Write-Host "Removing folder: $folder" -ForegroundColor Yellow
        try {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully removed folder: $folder" -ForegroundColor Green
        } catch {
            Write-Host "Failed to remove folder: $folder" -ForegroundColor Red
        }
    }
}
Write-Host "[APPLICATION REMOVAL COMPLETED]" -ForegroundColor Green
#endregion

#region SYSTEM CLEANUP & SETTINGS
Write-Host "`n[SECTION 2] SYSTEM CLEANUP & SETTINGS..." -ForegroundColor Yellow

# --- Remove Additional Bloatware (Windows Store Apps) ---
$additionalApps = @(
    "Microsoft.3DBuilder",
    "Microsoft.BingNews",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People",
    "Microsoft.SkypeApp",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MSPaint",
    "Microsoft.MixedReality.Portal"
)
foreach ($app in $additionalApps) {
    Write-Host "Removing $app..." -ForegroundColor White
    Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue |
        Remove-AppxPackage -ErrorAction SilentlyContinue
}

# --- Disable Cortana ---
Write-Host "Disabling Cortana..." -ForegroundColor White
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

# --- Display File Extensions and Hidden Files ---
Write-Host "Enabling file extensions and hidden file visibility..." -ForegroundColor White
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowSuperHidden -Value 1

# --- Set Control Panel to Icon View ---
Write-Host "Setting Control Panel view to icons..." -ForegroundColor White
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Value 1
#endregion

#region SYSTEM BEHAVIOR
Write-Host "`n[SECTION 3] SYSTEM BEHAVIOR..." -ForegroundColor Yellow

# --- Disable Transparency Effects ---
Write-Host "Disabling transparency..." -ForegroundColor White
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name EnableTransparency -Value 0

# --- Disable Toast Notifications ---
Write-Host "Disabling toast notifications..." -ForegroundColor White
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name ToastEnabled -Value 0
#endregion

#region ADDITIONAL CONFIGURATION
Write-Host "`n[SECTION 4] ADDITIONAL CONFIGURATION..." -ForegroundColor Yellow

# --- Disable Widgets on Lock Screen ---
Write-Host "Disabling lock screen widgets..." -ForegroundColor White
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Spotlight" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Spotlight" -Name "DisableWindowsSpotlightFeatures" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Spotlight" -Name "DisableSpotlightOnLockScreen" -Value 1

# --- Disable OneDrive ---
Write-Host "Disabling OneDrive..." -ForegroundColor White
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Value 1
Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$oneDriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
if (Test-Path $oneDriveSetup) {
    & $oneDriveSetup /uninstall
    Write-Host "OneDrive uninstalled." -ForegroundColor Green
} else {
    Write-Host "OneDrive setup executable not found." -ForegroundColor Yellow
}

# --- Set USB Autoplay to 'Do Nothing' ---
Write-Host "Setting USB autoplay to 'Do Nothing'..." -ForegroundColor White
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# --- Suppress Windows Security Recommended Actions ---
Write-Host "Suppressing Windows Security recommended actions..." -ForegroundColor White
$securityPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications"
New-Item -Path $securityPath -Force | Out-Null
Set-ItemProperty -Path $securityPath -Name "DisableEnhancedNotifications" -Value 1
#endregion

#region POWER SETTINGS & USER CONFIGURATION
Write-Host "`n[SECTION 5] POWER SETTINGS & USER CONFIGURATION..." -ForegroundColor Yellow

# --- Update Screen Timeout Settings ---
$acTimeout = 600   # 10 minutes when plugged in
$dcTimeout = 300   # 5 minutes when on battery
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"
Set-ItemProperty -Path $regPath -Name "ACSettingIndex" -Value $acTimeout
Set-ItemProperty -Path $regPath -Name "DCSettingIndex" -Value $dcTimeout
powercfg -SetActive SCHEME_BALANCED
Write-Host "Screen timeout settings have been updated." -ForegroundColor Green

# --- Configure Per-User Settings ---
$darkRed = "139 0 0"         # For Admin
$seaFoam = "159 226 191"      # For Other Users
$users = Get-ChildItem "HKU:\"
foreach ($user in $users) {
    $userSID = $user.PSChildName
    if ($userSID -match "S-\d-\d{2}-\d{6,}-\d{4,}") {
        try {
            $usernameValue = (Get-ItemProperty -Path "HKU:\$userSID\Volatile Environment" -ErrorAction SilentlyContinue).USERNAME
        } catch { $usernameValue = "" }
        $isAdmin = $usernameValue -eq "Admin"
        $bgColor = if ($isAdmin) { $darkRed } else { $seaFoam }

        Write-Host "Updating settings for user SID: $userSID (Background: $bgColor)" -ForegroundColor Yellow
        # Disable screensaver
        Set-ItemProperty -Path "HKU:\$userSID\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "0"
        Set-ItemProperty -Path "HKU:\$userSID\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -Value ""
        Set-ItemProperty -Path "HKU:\$userSID\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value "0"
        # Set background color and wallpaper settings
        Set-ItemProperty -Path "HKU:\$userSID\Control Panel\Colors" -Name "Background" -Value $bgColor
        Set-ItemProperty -Path "HKU:\$userSID\Control Panel\Desktop" -Name "Wallpaper" -Value ""
        Set-ItemProperty -Path "HKU:\$userSID\Control Panel\Desktop" -Name "WallpaperStyle" -Value "0"  # Center
        Set-ItemProperty -Path "HKU:\$userSID\Control Panel\Desktop" -Name "TileWallpaper" -Value "0"   # No tile
        # Focus Assist & Notification settings
        Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_TOASTS_ENABLED" -Value 2
        Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0
        Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0
        # Additional tweaks
        Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableConsumerFeatures" -Value 0
        Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
        Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0
        Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "Location" -Value 0
        Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoClose" -Value 0
        powercfg -h on
        Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Ads" -Value 0
        Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_ShowRecommendedApps" -Value 0
        if ($isAdmin) {
            Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
            Set-ItemProperty -Path "HKU:\$userSID\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1
        }
        Set-ItemProperty -Path "HKU:\$userSID\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "AUOptions" -Value 3
    }
}
Write-Host "User-specific settings have been updated." -ForegroundColor Green
#endregion

#region VERIFY POWERSHELL 7 INSTALLATION AND CONFIGURATION
Write-Host "`n[SECTION 6] VERIFY POWERSHELL 7 INSTALLATION AND CONFIGURATION..." -ForegroundColor Yellow

# --- Check if PowerShell 7 is installed ---
Write-Host "Checking if PowerShell 7 is installed..." -ForegroundColor White
$pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"
if (Test-Path $pwshPath) {
    Write-Host "PowerShell 7 is installed." -ForegroundColor Green
} else {
    Write-Host "PowerShell 7 is not installed. Downloading and installing..." -ForegroundColor Yellow
    $installerUrl = "https://github.com/PowerShell/PowerShell/releases/download/v7.5.0/PowerShell-7.5.0-win-x64.msi"
    $installerPath = "$env:TEMP\PowerShell-7.5.0-win-x64.msi"
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
    Start-Process msiexec.exe -ArgumentList "/i $installerPath /quiet /norestart" -Wait
    if (Test-Path $pwshPath) {
        Write-Host "PowerShell 7 installed successfully." -ForegroundColor Green
    } else {
        Write-Host "Failed to install PowerShell 7." -ForegroundColor Red
        return
    }
}

# --- Set PowerShell 7 as the default shell ---
Write-Host "Setting PowerShell 7 as the default shell..." -ForegroundColor White
$pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"
if (Test-Path $pwshPath) {
    # Update the PATH environment variable to prioritize PowerShell 7
    [Environment]::SetEnvironmentVariable("Path", "$pwshPath;$env:Path", [EnvironmentVariableTarget]::Machine)
    Write-Host "PowerShell 7 added to PATH." -ForegroundColor Green
} else {
    Write-Host "PowerShell 7 not found. Skipping default shell configuration." -ForegroundColor Yellow
}

# --- Disable PowerShell 7 Telemetry ---
Write-Host "Disabling PowerShell 7 telemetry..." -ForegroundColor White
$telemetryConfigPath = "$env:APPDATA\powershell\powershell.config.json"
if (-Not (Test-Path -Path $telemetryConfigPath)) {
    New-Item -ItemType File -Path $telemetryConfigPath -Force | Out-Null
}
$telemetryConfig = @{
    "PSCoreTelemetry" = @{
        "Enabled" = $false
    }
} | ConvertTo-Json -Depth 10
Set-Content -Path $telemetryConfigPath -Value $telemetryConfig -Force
Write-Host "PowerShell 7 telemetry disabled." -ForegroundColor Green

Write-Host "[POWERSHELL 7 CONFIGURATION COMPLETED]" -ForegroundColor Cyan
#endregion

#region FINAL CLEANUP ACTIONS
Write-Host "`n[SECTION 7] FINAL CLEANUP ACTIONS..." -ForegroundColor Yellow

# --- Clear Browser Data for Edge and IE ---
Write-Host "Clearing browser cache, cookies and history (Edge & IE)..." -ForegroundColor White
try {
    RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255
    Write-Host "Cleared browser data."
} catch {
    Write-Host "Error clearing browser data."
}

# --- Clear Recent File History ---
Write-Host "Clearing recent file history..." -ForegroundColor White
try {
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent Items\*" -Recurse -Force
    Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" | ForEach-Object {
        $_.PSObject.Properties | ForEach-Object {
            if ($_.Name -ne "MRUList") {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name $_.Name -Value $null
            }
        }
    }
    Write-Host "Cleared recent file history."
} catch {
    Write-Host "Error clearing recent file history."
}

# --- Clear PowerShell History ---
Write-Host "Clearing PowerShell command history..." -ForegroundColor White
try {
    $psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistoryPath) {
        Remove-Item -Path $psHistoryPath -Force
        Write-Host "Cleared PowerShell command history."
    }
} catch {
    Write-Host "Error clearing PowerShell history."
}

# --- Clear Clipboard Data ---
Write-Host "Clearing clipboard data..." -ForegroundColor White
try {
    Set-Clipboard -Value ""
    Write-Host "Cleared clipboard data."
} catch {
    Write-Host "Error clearing clipboard."
}

# --- Clear Temporary Files ---
Write-Host "Clearing temporary files..." -ForegroundColor White
try {
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force
    Write-Host "Cleared temporary files."
} catch {
    Write-Host "Error clearing temporary files."
}

# --- Clear Windows Prefetch Files ---
Write-Host "Clearing Windows prefetch files..." -ForegroundColor White
try {
    Remove-Item -Path "C:\Windows\Prefetch\*" -Recurse -Force
    Write-Host "Cleared Windows prefetch files."
} catch {
    Write-Host "Error clearing Windows prefetch files."
}
Write-Host "[FINAL CLEANUP ACTIONS COMPLETED]" -ForegroundColor Green
#endregion

#region FINISH
Write-Host "`n[SETUP SCRIPT COMPLETED]" -ForegroundColor Cyan
Write-Host "A system restart might be required for some changes to take full effect." -ForegroundColor Magenta
#endregion