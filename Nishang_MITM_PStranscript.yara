rule Nishang_MITM_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Man In The Middle section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Invoke_Interceptor_1 = "Invoke-Interceptor" nocase
		$Invoke_Interceptor_2 = "-Tamper" nocase
		$Invoke_Interceptor_3 = "Automatically detect proxy settings"
		$Invoke_Interceptor_4 = "Certificates Removed"
		$Invoke_Interceptor_5 = "Get Response Error"
		$Invoke_Interceptor_6 = "Adding certs"
		$Invoke_Interceptor_7 = "Using Proxy Server "
		$Invoke_Interceptor_8 = "Using Direct Internet Connection"
		$Invoke_Interceptor_9 = "Listening on "
    condition:
        any of them
}