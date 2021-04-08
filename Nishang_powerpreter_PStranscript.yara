rule Nishang_powerpreter_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Powerpreter section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs.  Almost all of the strings in Powerpreter are contained in the other Yara rules I wrote for Nishang"
    strings:
		$Powerpreter_1 = "Powerpreter" nocase
		$Powerpreter_2 = "LSA Secrets: " nocase
		$Powerpreter_3 = "Execute-DNSTXT-Code" nocase
		$Powerpreter_4 = "Starting PowerShell on the target.."
		$Powerpreter_5 = "Starting SQL shell on the target.."
		$Powerpreter_6 = "Starting cmd shell on the target.."
    condition:
        any of them
}