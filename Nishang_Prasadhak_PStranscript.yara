rule Nishang_Prasadhak_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Prasadhak section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Invoke_Prasadhak_1 = "Invoke-Prasadhak" nocase
		$Invoke_Prasadhak_2 = "Not found in VT database. "
		$Invoke_Prasadhak_3 = "Something malicious is found. "
		$Invoke_Prasadhak_4 = "This is reported clean. "
		$Invoke_Prasadhak_5 = "File queued for analysis. "
		$Invoke_Prasadhak_6 = "Reading Processes and determining executables."
		$Invoke_Prasadhak_7 = "Total Processes detected: "
		$Invoke_Prasadhak_8 = "Total Processes for which executables were detected: "
		$Invoke_Prasadhak_9 = "Waiting for one minute as VT allows only 4 requests per minute."
    condition:
        any of them
}