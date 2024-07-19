# PowerShell over SSH

This repo contains recommendations to enable PowerShell over SSH.

The enable_ssh.ps1 script performs all operations except the PowerShell 7 installation.

## Scripted approach

Run in PowerShell, as an admin user:

```ps1
.\enable_ssh.ps1
```

##  Manual approach

### Software prerequisites on the server

PowerShell 7 or higher

Install it with https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.4

### Enable OpenSSH Server

```ps1
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start the sshd service
Start-Service sshd

# OPTIONAL but recommended:
Set-Service -Name sshd -StartupType 'Automatic'

# Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}
```

### Configure SSH authentication and allow SSH to run PowerShell

Doc: https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell?view=powershell-7.4

Change this in `C:/ProgramData/ssh/sshd_config`

```
PasswordAuthentication yes
PubkeyAuthentication yes
Subsystem powershell c:/progra~1/powershell/7/pwsh.exe -sshs -nologo
```

### Restart SSH Service

```ps1
Restart-Service sshd
```

### Add SSH public keys for standard users

Doc: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement

```ps1
$authorizedKey = "<PUBKEY>"
$user = "<USERNAME>"
Add-Content -Force -Path C:\Users\$user\.sshauthorized_keys -Value "$authorizedKey"
```


### Add SSH public keys for administrative user

Doc: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement

```ps1
$authorizedKey = "<PUBKEY>"
Add-Content -Force -Path $env:ProgramData\ssh\administrators_authorized_keys -Value "$authorizedKey"
# for english systems
icacls.exe "$env:ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
# for all systems
icacls.exe "$env:ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "*S-1-5-32-544:F" /grant "SYSTEM:F"
```


