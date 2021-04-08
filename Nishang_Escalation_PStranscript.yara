rule Nishang_Escalation_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Escalation section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Enable_DuplicateToken = "Enable-DuplicateToken" nocase
		$Invoke_PsUACme_1 = "Invoke-PsUACme" nocase
		$Invoke_PsUACme_2 = "Reading 64 bit DLL."
		$Invoke_PsUACme_3 = "Reading 32 bit DLL."
		$Invoke_PsUACme_4 = "64 bit process detected."
		$Invoke_PsUACme_5 = "32 bit process detected."
		$Invoke_PsUACme_6 = "Using Sysprep method"
		$Invoke_PsUACme_7 = "Windows 7 found!"
		$Invoke_PsUACme_8 = "Windows 8 found!"
		$Invoke_PsUACme_9 = "Windows 10 found. Wusa.exe on Windows 10 has no extract option. Not supported "
		$Invoke_PsUACme_10 = "Using OOBE method"
		$Invoke_PsUACme_11 = "Writing DLLs to Temp directory"
		$Invoke_PsUACme_12 = "Using Sysprep Actionqueue method"
		$Invoke_PsUACme_13 = "This method doesn't work Windows 8.1 onwards."
		$Invoke_PsUACme_14 = "Using migwiz method"
		$Invoke_PsUACme_15 = "Using cliconfg method"
		$Invoke_PsUACme_16 = "Using winsat method"
		$Invoke_PsUACme_17 = "Copying C:\\Windows\\System32\\winsat.exe to "
		$Invoke_PsUACme_18 = "Using mmc method"
		$Invoke_PsUACme_19 = " must be removed manually."
		$Remove_Update_1 = "Remove-Update" nocase
		$Remove_Update_2 = "Removing update "
		$Remove_Update_3 = "Removing Security Update "
		$Remove_Update_4 = "Waiting for update removal to finish ..."
    condition:
        any of them
}