<#
.SYNOPSIS
    Creates a deliberately misconfigured Windows service to demonstrate insecure service permissions.

.DESCRIPTION
    This PowerShell script sets up a vulnerable Windows service by:
    - Creating a directory and a dummy service executable file
    - Assigning full control of the service binary path to a low-privileged user
    - Creating a service that runs as LocalSystem
    - Granting the user permission to modify the service configuration

    This is intended for lab environments ONLY to demonstrate privilege escalation techniques.

.NOTES
    Author: Your Name
    Date: 2025-05-25
    Use only in isolated environments!
#>

# ----------------------------
# Configuration
# ----------------------------

# Username of the low-privileged user (local account, no domain prefix)
$User = "test"

# Service details
$ServiceName = "VulnService"
$ServiceDisplayName = "Vulnerable Service"
$ServiceFolder = "C:\VulnService"
$ServiceExePath = Join-Path $ServiceFolder "service.exe"

# ----------------------------
# Step 1: Create Service Folder
# ----------------------------
Write-Host "[+] Creating vulnerable service directory at $ServiceFolder"
New-Item -Path $ServiceFolder -ItemType Directory -Force | Out-Null

# Create a dummy executable file
Write-Host "[+] Creating dummy service executable"
"Fake binary content" | Out-File -FilePath $ServiceExePath -Encoding ASCII -Force

# ----------------------------
# Step 2: Set Folder Permissions
# ----------------------------
Write-Host "[+] Granting full control of $ServiceFolder to user '$User'"
icacls $ServiceFolder /grant "$User:(OI)(CI)F" /T

# ----------------------------
# Step 3: Create the Service
# ----------------------------
Write-Host "[+] Creating Windows service '$ServiceName'"
New-Service -Name $ServiceName `
            -BinaryPathName "`"$ServiceExePath`"" `
            -DisplayName $ServiceDisplayName `
            -StartupType Manual

# ----------------------------
# Step 4: Make the Service Permissions Insecure
# ----------------------------

# This SDDL grants the "Authenticated Users" group (AU) full control over the service config
# You can replace AU with the specific user SID if needed
$InsecureSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;AU)"

Write-Host "[+] Applying insecure service permissions (SDDL)"
Start-Process -FilePath "sc.exe" -ArgumentList "sdset $ServiceName $InsecureSDDL" -Wait -NoNewWindow

# ----------------------------
# Done
# ----------------------------
Write-Host "`n[+] Vulnerable service '$ServiceName' created successfully."
Write-Host "[!] User '$User' now has full control over the service binary and configuration."
Write-Host "[!] This setup is vulnerable to privilege escalation. Use in lab environments only!"
