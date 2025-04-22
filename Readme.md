# Laptop Configuration Scripts Bundle

This repository contains various PowerShell scripts and notes which I'm using to configure and manage a group of Windows laptops.  I've ommitted endpoint protection and policies for security reasons.

## Scripts

Use this to run:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Desktop\scriptname.ps1"
```

### CleanUpUser.ps1

This script is used to clean up the local user accounts. This is only necessary if Deepfreeze hasn't been initiated after a rebuild.

### FirstSetup.ps1

This script is used to set up the initial configuration for the system.  
It includes:

- Setting up the environment
- Installing necessary packages
- Configuring settings

### Install_Apps.ps1

This script is used to install necessary applications on the system.  
It includes:

- Installing software
- Configuring settings
- Setting up the environment

## Additional Notes

### Updating Applications

You can update apps manually by running the following command:

```powershell
winget upgrade --all --silent --accept-source-agreements --accept-package-agreements
```

### Documentation

- [Winget Documentation](https://learn.microsoft.com/en-us/windows/package-manager/winget/)

### WinUtil by ChrisTitus.com

WinUtil: A PowerShell script that provides various functions and features for Windows systems.

```powershell
irm "https://christitus.com/win" | iex
```

This is a utility script that provides various functions and features for Windows systems.
It includes system optimization, application management, and other useful features.
You can find more information about WinUtil at:
<https://christitus.com/winutil/>
