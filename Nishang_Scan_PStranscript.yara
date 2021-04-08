rule Nishang_Scan_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Scan section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Invoke_BruteForce_1 = "Invoke-BruteForce" nocase
		$Invoke_BruteForce_2 = "-Service ActiveDirectory" nocase
		$Invoke_BruteForce_3 = "-Service LocalAccounts" nocase
		$Invoke_BruteForce_4 = "Starting Brute-Force with a Delay of "
		$Invoke_BruteForce_5 = "UserList file does not exist. Using UserList as usernames:"
		$Invoke_BruteForce_6 = "PasswordList file does not exist. Using PasswordList as passwords:"
		$Invoke_BruteForce_7 = "Match found! "
		$Invoke_BruteForce_8 = "Brute Forcing SQL Service on "
		$Invoke_BruteForce_9 = "Brute Forcing FTP on "
		$Invoke_BruteForce_10 = "Brute Forcing Active Directory "
		$Invoke_BruteForce_11 = "Brute Forcing Local Accounts "
		$Invoke_BruteForce_12 = "Password doesn't match"
		$Invoke_PortScan_1 = "Invoke-PortScan" nocase
		$Invoke_PortScan_2 = "-StartAddress" nocase
		$Invoke_PortScan_3 = "-EndAddress" nocase
		$Invoke_PortScan_4 = "-ScanPort" nocase
		$Invoke_PortScan_5 = "PingSweep "
		$Invoke_PortScan_6 = "PortScan "
    condition:
        any of them
}