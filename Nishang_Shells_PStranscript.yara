rule Nishang_Shells_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Shells section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Invoke_ConPtyShell_1 = "Invoke-ConPtyShell" nocase
		$Invoke_ConPtyShell_2 = "-RemoteIp" nocase
		$Invoke_ConPtyShell_3 = "-RemotePort" nocase
		$Invoke_ConPtyShell_4 = "ConPtyShell" nocase
		$Invoke_ConPtyShell_5 = "Could not get console mode"
		$Invoke_ConPtyShell_6 = "Could not calculate the number of bytes for the attribute list. "
		$Invoke_ConPtyShell_7 = "Could not set up attribute list. "
		$Invoke_ConPtyShell_8 = "Could not set pseudoconsole thread attribute. "
		$Invoke_ConPtyShell_9 = "Could not create process. "
		$Invoke_ConPtyShell_10 = "Could not connect to ip "
		$Invoke_ConPtyShell_11 = "CreatePseudoConsole function not found! Spawning a netcat-like interactive shell..."
		$Invoke_ConPtyShell_12 = "CreatePseudoConsole function found! Spawning a fully interactive shell..."
		$Invoke_ConPtyShell_13 = "Could not create psuedo console. Error Code "
		$Invoke_ConPtyShell_14 = "ConPtyShell: "
		$Invoke_JSRatRegsrv_1 = "Invoke-JSRatRegsrv" nocase
		$Invoke_JSRatRegsrv_2 = "Listening on "
		$Invoke_JSRatRegsrv_3 = "Run the following command on the target:"
		$Invoke_JSRatRegsrv_4 = "regsvr32.exe /u /n /s /i:http"
		$Invoke_JSRatRegsrv_5 = "cmd /c taskkill /f /im regsvr32.exe"
		$Invoke_JSRatRundll_1 = "Invoke-JSRatRundll" nocase
		$Invoke_JSRatRundll_2 = "rundll32.exe javascript:"
		$Invoke_JSRatRundll_3 = "Host Connected"
		$Invoke_JSRatRundll_4 = "cmd /c taskkill /f /im rundll32.exe"
		$Invoke_PoshRatHttp_1 = "Invoke-PoshRatHttp" nocase
		$Invoke_PoshRatHttp_2 = "Something went wrong! Check if client could reach the server and using the correct port."
		$Invoke_PoshRatHttps_1 = "Invoke-PoshRatHttps" nocase
		$Invoke_PoshRatHttps_2 = "Receive-ClientHttpsRequest" nocase
		$Invoke_PoshRatHttps_3 = "Connect Request Received"
		$Invoke_PoshRatHttps_4 = "/rat"
		$Invoke_PowerShellIcmp_1 = "Invoke-PowerShellIcmp" nocase
		$Invoke_PowerShellIcmp_2 = "Windows PowerShell running as user "
		$Invoke_PowerShellTcp_1 = "Invoke-PowerShellTcp" nocase
		$Invoke_PowerShellTcp_2 = "Something went wrong with execution of command on the target."
		$Invoke_PowerShellTcpOneLine_1 = "Invoke-PowerShellTcpOneLine" nocase
		$Invoke_PowerShellTcpOneLine_2 = "$sendback + 'PS '"
		$Invoke_PowerShellTcpOneLineBind_1 = "Invoke-PowerShellTcpOneLineBind" nocase
		$Invoke_PowerShellTcpOneLineBind_2 = "listener.start"
		$Invoke_PowerShellTcpOneLineBind_3 = "[System.Net.Sockets.TcpListener]"
		$Invoke_PowerShellUdp = "Invoke-PowerShellUdp" nocase
		$Invoke_PowerShellUdpOneLine_1 = "Invoke-PowerShellUdpOneLine" nocase
		$Invoke_PowerShellUdpOneLine_2 = "New-Object System.Net.Sockets.UDPClient"
		$Invoke_PowerShellUdpOneLine_3 = "PS> "
		$Invoke_PowerShellWmi_1 = "Invoke-PowerShellWmi" nocase
		$Invoke_PowerShellWmi_2 = "Payload " nocase
		$Invoke_PowerShellWmi_3 = "PayloadScript " nocase
		$Invoke_PowerShellWmi_4 = "Execute-WmiCommand" nocase
		$Invoke_PowerShellWmi_5 = "Sending given command to a scriptblock"
		$Invoke_PowerShellWmi_6 = "Creating Scriptblock to execute on "
		$Invoke_PowerShellWmi_7 = "Waiting for the scriptblock on "
		$Invoke_PowerShellWmi_8 = "Retrieving command output"
		$Invoke_PowerShellWmi_9 = "Cleaning up the target system"
		$Invoke_PowerShellWmi_10 = "Decoding the encoded output."
		$Invoke_PSGcat_1 = "Invoke-PSGcat" nocase
		$Invoke_PSGcat_2 = "PsGcat: "
		$Invoke_PSGcat_3 = "Command sent to "
		$Invoke_PSGcat_4 = "Something went wrong! Check if Username/Password are correct and you can connect to gmail from insecure apps."
		$Invoke_PSGcat_5 = "You were not authenticated. Quitting."
		$Invoke_PSGcat_6 = "You are not connected to the host. Quitting"
		$Invoke_PSGcat_7 = "Something went wrong! Check if Username/Password are correct, you can connect to gmail from insecure apps and if there is output email in the inbox"
		$Invoke_PSGcat_8 = "Reading Output from Gmail"
		$Invoke_PSGcat_9 = "Sending Payload to "
		$Invoke_PSGcat_10 = "Use GetOutput to get output."
		$Invoke_PSGcat_11 = "Use Script to specify a script."
		$Invoke_PSGcat_12 = "Provide complete path to the PowerShell script."
		$Invoke_PSGcatAgent_1 = "Invoke-PSGcatAgent" nocase
		$Invoke_PSGcatAgent_2 = "Executing Encoded Command "
		$Remove_PoshRat = "Remove-PoshRat" nocase
    condition:
        any of them
}