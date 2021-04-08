rule Nishang_Backdoor_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Backdoor section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Add_RegBackdoor = "Add-RegBackdoor" nocase
		$Add_ScrnSaveBackdoor_1 = "Add-ScrnSaveBackdoor" nocase
		$Add_ScrnSaveBackdoor_2 = "Payload added as Debugger for "
		$DNS_TXT_Pwnage_1 = "DNS_TXT_Pwnage" nocase
		$DNS_TXT_Pwnage_2 = "-CommandDomain" nocase
		$Execute_OnTime = "Execute-OnTime" nocase
		$Gupt_Backdoor_1 = "Gupt-Backdoor" nocase
		$Gupt_Backdoor_2 = "Found a network with instructions"
		$Gupt_Backdoor_3 = "PowerShell v3 or above in use. Downloading the attack script at"
		$HTTP_Backdoor = "HTTP-Backdoor" nocase
		$Invoke_ADSBackdoor_1 = "Invoke-ADSBackdoor" nocase
		$Invoke_ADSBackdoor_2 = "Process Complete. Persistent key is located at HKCU"
		$Set_RemotePSRemoting_1 = "Set-RemotePSRemoting" nocase
		$Set_RemotePSRemoting_2 = "Existing ACL for PSRemoting is "
		$Set_RemotePSRemoting_3 = "Updating ACL for PSRemoting."
		$Set_RemotePSRemoting_4 = "New ACL for PSRemoting is "
		$Set_RemoteWMI_1 = "Set-RemoteWMI" nocase
		$Set_RemoteWMI_2 = "-NotAllNamespaces"
		$Set_RemoteWMI_3 = "Existing ACL for namespace "
		$Set_RemoteWMI_4 = "Existing ACL for DCOM is "
		$Set_RemoteWMI_5 = "New ACL for namespace "
		$Set_RemoteWMI_6 = "New ACL for DCOM "
    condition:
        any of them
}