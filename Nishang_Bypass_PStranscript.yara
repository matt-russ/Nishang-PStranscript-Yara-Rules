rule Nishang_Bypass_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Bypass section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Bypass_1 = "Invoke-AmsiBypass" nocase
		$Bypass_2 = "Invoke-PsUACme" nocase
		$Bypass_3 = "Using Matt Graeber's Reflection method."
		$Bypass_4 = "Use the following scriptblock before you run a script which gets detected."
		$Bypass_5 = "Executing the bypass."
		$Bypass_6 = "Using Cornelis de Plaa's DLL hijack method."
		$Bypass_7 = "Copy powershell.exe from C:\\Windows\\System32\\WindowsPowershell\\v1.0 to a local folder and dropa fake amsi.dll in the same directory."
		$Bypass_8 = "Run the new powershell.exe and AMSI should be gone for that session."
		$Bypass_9 = "Dropping the fake amsi.dll to disk."
		$Bypass_10 = "Copying powershell.exe to the current working directory."
		$Bypass_11 = "Starting powershell.exe from the current working directory."
		$Bypass_12 = "Using PowerShell version 2 which doesn't support AMSI."
		$Bypass_13 = "AMSI and the AVs which support it can be bypassed using obfuscation techqniues."
    condition:
        any of them
}