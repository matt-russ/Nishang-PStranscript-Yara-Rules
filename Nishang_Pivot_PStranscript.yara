rule Nishang_Pivot_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Pivot section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Create_MultipleSessions_1 = "Create-MultipleSessions" nocase
		$Create_MultipleSessions_2 = "Credentials worked on "
		$Create_MultipleSessions_3 = "Creating Session for "
		$Create_MultipleSessions_4 = "Could not connect or credentials didn't work on "
		$Create_MultipleSessions_5 = "Following Sessions have been created: "
		$Invoke_NetworkRelay_1 = "Invoke-NetworkRelay" nocase
		$Invoke_NetworkRelay_2 = " v4tov4"
		$Invoke_NetworkRelay_3 = " v4tov6"
		$Invoke_NetworkRelay_4 = " v6tov6"
		$Invoke_NetworkRelay_5 = " v6tov4"
		$Run_EXEonRemote = "Run-EXEonRemote" nocase
    condition:
        any of them
}