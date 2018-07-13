'''
@author: Jaycob Garcia

This program is used to secure then computer.

'''
import subprocess, os

operatingSystem = input(str(''' 
 This is The Securotron 2000. This program will make a computer as secure as possible
 by changing any unsecure settings, removing viruses, rootkits, keyloggers, etc...,
 enabling a Firewall, and any other security measures that will prevent attacks on the computer  
 It can be used on both Windows and Linux, but not Mac as we do not condone self harm.
 If you are a Mac user, please contact the suicide prevention Hotline at (1-800-273-8255)
 
 Which Operating System are you running this Program on?
 
 Windows = W                                                 Linux = L
 
 Input here: '''))

if operatingSystem == 'W' or operatingSystem == 'w':
    
    Permissions = input(str('''
 At every step the program will ask for permission to complete a task. You can let 
 the program run without asking for permissions by entering FP after reading through 
 the excerpt. Please make sure that you read and understand what you are agreeing 
 to when you give permissions to the program.
 
 This is a list of tasks that will be completed by the program:
 
 1. Enable FireWall
 2. Enable UAC
 3. Disable Remote Desktop
 4. Run Updates
 5. Set Host file to default
 6. Set Services to Default
 7. Disable Unsecure Windows Features
 8. Set Internet Settings to default
 9. Enable Secure Group Policy Settings (Complex Passwords, Encrypted Passwords, etc...)
10. Delete all Media Files 
11. Disable Admin Accounts
12. Enable FireWall
13. Set a Secure permissions standard for users
14. Delete all hacking tools present of the System
15. Repair any broken or corrupted files
16. Delete Rootkits, Viruses, Malware, Malicious Applications, etc...
17. Set Startup programs to default
18. Show Extensions
19. Set Scheduled Tasks to Default
20. Disable Hidden Files
21. Set shares to default
22. Disable Remote Assistance
23. Set Secure Power Settings
24. Install Service Packs
25. Enable Auditing
26. Disable and Purge Ubuntu Core from the System 

 FP = Full Permissions                                       p = Ask for Permissions

 Input here: '''))
    
    # Sets Password policy, Auditing policy
    passwdAndAudit = open(r'C:\secconfig.cfg', 'w+')
    passwdAndAudit.write(r'''
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 5
MaximumPasswordAge = 90
MinimumPasswordLength = 8
PasswordComplexity = 1
PasswordHistorySize = 5
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
NewAdministratorName = "Administrator"
NewGuestName = "Guest"
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
EnableAdminAccount = 0
EnableGuestAccount = 0
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3
[Registry Values]
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"10"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,5
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,"0"
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,3
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Posecedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfig.cfg /areas SECURITYPOLICYlicies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,""
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures=4,0
MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing=3,0
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,536870912
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,536870912
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,0
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog
MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown=4,0
MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,0
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,0
MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeSystemtimePrivilege = *S-1-5-19,*S-1-5-32-544
SeCreatePagefilePrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0
SeLoadDriverPrivilege = *S-1-5-32-544
SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559
SeServiceLogonRight = *S-1-5-80-0
SeInteractiveLogonRight = Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeSecurityPrivilege = *S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = Guest
SeDenyInteractiveLogonRight = Guest
SeUndockPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeManageVolumePrivilege = *S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeIncreaseWorkingSetPrivilege = *S-1-5-32-545
SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-545
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDelegateSessionUserImpersonatePrivilege = *S-1-5-32-544
[Version]
signature="$CHICAGO$"
Revision=1''')
    subprocess.call(r'secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfig.cfg /areas SECURITYPOLICY')
    # Sets Services to default
    with open('defaultServices') as file:
        defaultServices = file.readlines()
    for service in defaultServices:
        subprocess.call(str(service))
    # Sets Features to default
        #Disables
    with open('disabledFeatures') as file:
        disabledFeatures = file.readlines()
    for feature in disabledFeatures:
        subprocess.call(str(feature))
        # Enables
    with open('enabledFeatures') as file:
        enabledFeatures = file.readlines()
    for feature in enabledFeatures:
        subprocess.call(str(feature))
    # Resets GroupPolicy to default
    subprocess.call('RD /S /Q "%WinDir%\System32\GroupPolicyUsers"')
    subprocess.call('RD /S /Q "%WinDir%\System32\GroupPolicy"')
    subprocess.call('gpupdate /force')
    # Resets host file to default
    if os.path.isfile(r'C:\Windows\System32\drivers\etc\hosts'):
        os.remove(r'C:\Windows\System32\drivers\etc\hosts')
    else:
        print(r'Host file was not able to be removed, hosts was not in C:\Windows\System32\drivers\etc\'')
    file = open(r'C:\Users\Public\hosts', 'w+')
    file.write(r'''
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host
# localhost name resolution is handled within DNS itself.
#       127.0.0.1       localhost
#       ::1             localhost''')
    os.rename(r'C:\Users\Public\hosts', r'C:\Windows\System32\drivers\etc\hosts')
    # Resets firewall to default, starts firewall, and sets exceptions
    subprocess.call('netsh advfirewall reset')
    subprocess.call('netsh advfirewall set allprofiles state on')
    subprocess.call('netsh advfirewall firewall add rule name="All ICMP V4" dir=in action=block protocol=icmpv4')
    
    # Runs Updates
    subprocess.call('wuauclt.exe /updatenow')
    # System File Check
    subprocess.call(r'sfc /scannow')
    # Make the computer run updates at startup
    subprocess.call(r'reg add HKEY_LOCAL _MACHINE\SOFTWARE\Microsoft\Windows\Current\Version\Run /v "Updates" /t REG_SZ /d "wuauctl.exe /updatenow')
    # Turns on File Extentions
    subprocess.call(r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f')
    # Turns on UAC
    subprocess.call(r'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f')
    # Turns off proxy in Internet Settings
    subprocess.call(r'REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f')
    # Computer sleep after 5 mins of inactivity and to lock if asleep 
    subprocess.call(r'powercfg /SETACVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 300')
    subprocess.call(r'powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 300')
    # Gets the User Names of all users on the system
    subprocess.call(r'net users > C:\Users\Public\users.txt')
    # Gets the names of all the groups on the system
    subprocess.call(r'net localgroup > C:\Users\Public\groups.txt')

if operatingSystem == 'L' or operatingSystem == 'l':
    
    Permissions = input(str('''
 At every step the program will ask for permission to complete a task. You can let 
 the program run without asking for permissions by entering FP after reading through 
 the excerpt. Please make sure that you read and understand what you are agreeing 
 to when you give permissions to the program.
 
 This is a list of tasks that will be completed by the program:
 
 1. 

 FP = Full Permissions                                       p = Ask for Permissions

 Input here: '''))


