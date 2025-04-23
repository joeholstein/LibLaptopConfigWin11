# Lib Laptop Configuration for Windows 11

This repository contains various PowerShell scripts and notes which I'm using to configure and manage a group of Windows laptops. I've omitted endpoint protection and policies for security reasons.

## Disclaimer

**WARNING:**  
These scripts modify system settings, install or remove applications, and perform various system optimizations. **Use them at your own risk.**  
The author is not responsible for any damage, data loss, or system instability that may occur as a result of using these scripts. Always ensure you have complete backups and fully understand the changes being made before executing them. Contributions, issues, or modifications are welcome, but please be cautious in production environments.

## License

This repository is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Scripts

Copy&Paste this as admin to run:

```powershell
powershell -ExecutionPolicy Bypass -File ".\FirstSetup.ps1"
```

```powershell
powershell -ExecutionPolicy Bypass -File ".\Install_Apps.ps1"
```

```powershell
powershell -ExecutionPolicy Bypass -File ".\CleanUpUser.ps1"
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
