# This script enables and configures PowerShell over SSH

##############
# SETTINGS
##############

$pwsh7Path = "C:\Program Files\PowerShell\7\pwsh.exe"
$enable_password_authentication = 'yes' # set it to no otherwise
$enable_pubkey_authentication = 'yes' # set it to no otherwise
$sshd_config = "$env:ProgramData\ssh\sshd_config"
$set_pubkeys_standard_users = $True
$set_pubkeys_administrative_user = $True
$sid_admin_group = "S-1-5-32-544"

$pubkeys_standard_users = @{
    'user1' = @(
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDf',
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDf'
    )
    'user2' = @(
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDf',
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDf'
    )
}

$pubkeys_administrative_user = @(
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDf',
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDf'
    )


####################################################################################################
# Prerequisite: PowerShell 7 or higher
####################################################################################################



# Check if the file exists
if (Test-Path $pwsh7Path) {
    Write-Output "PowerShell 7 is installed."
} else {
    Write-Output "PowerShell 7 is not installed. Please install it before running the program. Stopping the program..."
    exit 1
}

####################################################################################################
# First install SSH and configure firewall
# Source: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.4#msi
####################################################################################################

# Install SSH server
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

####################################################################################################
# Edit sshd_config
# Source: https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell?view=powershell-7.4
####################################################################################################

# Set PasswordAuthentication yes or no
$sshd_config_content = Get-Content -Path $sshd_config
$sshd_config_edited = $False

$setting_to_write = 'PasswordAuthentication '+$enable_password_authentication

$sshd_config_content | ForEach-Object {
    # Look for PasswordAuthentication and set it to yes
    if ($_ -match '^#?PasswordAuthentication') {
        # Replace the line with PasswordAuthentication yes
        $_ -replace '^#?PasswordAuthentication.*', $setting_to_write
        $sshd_config_edited = $True
    } else {
        $_ 
    }
} | Set-Content -Path $sshd_config

# If not edited, add PasswordAuthentication yes or no to the end of the file
if (-not $sshd_config_edited) {
    Add-Content -Path $sshd_config -Value $setting_to_write
}

# Set PubkeyAuthentication yes or no
$sshd_config_content = Get-Content -Path $sshd_config
$sshd_config_edited = $False

$setting_to_write = 'PubkeyAuthentication '+$enable_pubkey_authentication

$sshd_config_content | ForEach-Object {
    # Look for PubkeyAuthentication and set it to yes or no
    if ($_ -match '^#?PubkeyAuthentication') {
        # Replace the line with PubkeyAuthentication yes or no
        $_ -replace '^#?PubkeyAuthentication.*', $setting_to_write
        $sshd_config_edited = $True
    } else {
        $_ 
    }
} | Set-Content -Path $sshd_config

# If not edited, add PubkeyAuthentication yes or no to the end of the file
if (-not $sshd_config_edited) {
    Add-Content -Path $sshd_config -Value $setting_to_write
}

# Do the same for Subsystem
# Subsystem powershell c:/progra~1/powershell/7/pwsh.exe -sshs -nologo
$sshd_config_content = Get-Content -Path $sshd_config
$sshd_config_edited = $False

$setting_to_write = 'Subsystem powershell c:/progra~1/powershell/7/pwsh.exe -sshs -nologo'

$sshd_config_content | ForEach-Object {
    # Look for Subsystem and set it to powershell
    if ($_ -match '^#?Subsystem') {
        # Replace the line with Subsystem powershell
        $_ -replace '^#?Subsystem.*', $setting_to_write
        $sshd_config_edited = $True
    } else {
        $_ 
    }
} | Set-Content -Path $sshd_config

# If not edited, add Subsystem powershell to the end of the file
if (-not $sshd_config_edited) {
    Add-Content -Path $sshd_config -Value $setting_to_write
}


####################################################################################################
# Restart the sshd service
####################################################################################################

Restart-Service sshd

####################################################################################################
# Set public keys for standard users
####################################################################################################

if ($set_pubkeys_standard_users) {
    foreach ($user in $pubkeys_standard_users.Keys) {
        $ssh_standard_user_path = "C:\Users\$user\.ssh"
        New-Item -Force -ItemType Directory -Path $ssh_standard_user_path
        $authorized_keys = "$ssh_standard_user_path\authorized_keys"
        $pubkeys = $pubkeys_standard_users[$user]

        if (-not (Test-Path $authorized_keys)) {
            New-Item -Path $authorized_keys -ItemType File
        }

        $pubkeys | ForEach-Object {
            Add-Content -Path $authorized_keys -Value $_
        }
    }
}

####################################################################################################
# Set public keys for administrative user
####################################################################################################

if ($set_pubkeys_administrative_user) {
    $ssh_administrative_user_path = "C:\ProgramData\ssh"
    New-Item -Force -ItemType Directory -Path $ssh_administrative_user_path
    $authorized_keys = "$ssh_administrative_user_path\administrators_authorized_keys"

    if (-not (Test-Path $authorized_keys)) {
        New-Item -Path $authorized_keys -ItemType File
    }

    $pubkeys_administrative_user | ForEach-Object {
        Add-Content -Path $authorized_keys -Value $_
    }

    icacls.exe $authorized_keys /inheritance:r /grant "\*$sid_admin_group\:F" /grant "SYSTEM:F"
}
