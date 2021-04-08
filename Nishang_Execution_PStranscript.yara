rule Nishang_Execution_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Execution section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Download_Execute_PS_1 = "Download-Execute-PS" nocase
		$Download_Execute_PS_2 = "-nodownload" nocase
		$Download_Execute = "Download_Execute" nocase
		$Execute_Command_MSSQL_1 = "Execute-Command-MSSQL" nocase
		$Execute_Command_MSSQL_2 = "Do you want a PowerShell shell (P) or a SQL Shell (S) or a cmd shell (C):"
		$Execute_Command_MSSQL_3 = "Starting PowerShell on the target.."
		$Execute_Command_MSSQL_4 = "Starting SQL shell on the target.."
		$Execute_Command_MSSQL_5 = "Starting cmd shell on the target.."
		$Execute_Command_MSSQL_6 = "Connecting to target..."
		$Execute_Command_MSSQL_7 = "Enabling XP_CMDSHELL..."
		$Execute_DNSTXT_Code_1 = "Execute-DNSTXT-Code" nocase
		$Execute_DNSTXT_Code_2 = "-ShellCode32" nocase
		$Execute_DNSTXT_Code_3 = "-ShellCode64" nocase
		$Execute_DNSTXT_Code_4 = "Get-ShellCode" nocase
		$Out_RundllCommand_1 = "Out-RundllCommand" nocase
		$Out_RundllCommand_2 = "Copy the command from the "
    condition:
        any of them
}