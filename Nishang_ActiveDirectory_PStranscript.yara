rule Nishang_ActiveDirectory_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Active Directory section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Add_ConstrainedDelegationBackdoor_ps1_1 = "Add-ConstrainedDelegationBackdoor" nocase
		$Add_ConstrainedDelegationBackdoor_ps1_2 = "msDS-AllowedToDelegateTo " nocase
		$Add_ConstrainedDelegationBackdoor_ps1_3 = " to be trusted for delegation."
		$Add_ConstrainedDelegationBackdoor_ps1_4 = "-AllowedToDelegateTo " nocase
		$Set_DCShadowPermissions_ps1_1 = "Set-DCShadowPermissions" nocase
		$Set_DCShadowPermissions_ps1_2 = "-FakeDC " nocase
		$Set_DCShadowPermissions_ps1_3 = " to be registered as Fake DC"
    condition:
        any of them
}