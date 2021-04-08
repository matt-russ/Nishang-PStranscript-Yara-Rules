rule Nishang_Utility_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Utility section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Add_Exfiltration_1 = "Add-Exfiltration" nocase
		$Add_Exfiltration_2 = "ExfilOption gmail" nocase
		$Add_Exfiltration_3 = "ExfilOption pastebin" nocase
		$Add_Exfiltration_4 = "ExfilOption webserver" nocase
		$Add_Exfiltration_5 = "ExfilOption DNS" nocase
		$Add_Persistence_1 = "Add-Persistence" nocase
		$Add_Persistence_2 = "Writing payload to "
		$Add_Persistence_3 = "Writing VBScript to "
		$Add_Persistence_4 = "Creating reboot persistence. The payload executes on every computer restart"
		$Add_Persistence_5 = "Creating a filter with name "
		$Add_Persistence_6 = "Please specify a payload script or URL!"
		$Add_Persistence_7 = "Not running with elevated privileges. Using RUn regsitry key"
		$Base64ToString_1 = "Base64ToString " nocase
		$Base64ToString_2 = "Decoded data written to file "
		$ConvertTo_ROT13_1 = "ConvertTo-ROT13" nocase
		$ConvertTo_ROT13_2 = "rot13string" nocase
		$Do_Exfiltration = "Do-Exfiltration" nocase
		$ExetoText_1 = "ExetoText " nocase
		$ExetoText_2 = "Converted file written to "
		$Invoke_Decode_1 = "Invoke-Decode" nocase
		$Invoke_Decode_2 = "-EncodedData" nocase
		$Invoke_Decode_3 = "Decode data written to "
		$Invoke_Encode_1 = "Invoke-Encode" nocase
		$Invoke_Encode_2 = "PostScriptCommand" nocase
		$Invoke_Encode_3 = "Encoded data written to "
		$Invoke_Encode_4 = "Encoded command written to "
		$OUT_DNSTXT_1 = "OUT-DNSTXT" nocase
		$OUT_DNSTXT_2 = "-DataToEncode" nocase
		$OUT_DNSTXT_3 = "You need to create "
		$OUT_DNSTXT_4 = "All TXT Records written to "
		$OUT_DNSTXT_5 = "TXT Record could fit in single subdomain."
		$OUT_DNSTXT_6 = "TXT Records written to "
		$Parse_Keys = "Parse_Keys" nocase
		$Remove_Persistence_1 = "Remove-Persistence" nocase
		$Remove_Persistence_2 = "Please make sure to verufy the root\\subscription entries before using the -Remove option"
		$Remove_Persistence_3 = "Run the Command as an Administrator. Removing Registry keys only."
		$Remove_Persistence_4 = "Removing the WMI Events."
		$Remove_Persistence_5 = "Removing the Registry keys."
		$Remove_Persistence_6 = "Run Registry key persistence found. Use with -Remove option to clean."
		$Remove_Persistence_7 = "WMI permanent event consumer persistence found. Use with -Remove option to clean."
		$Start_CaptureServer = "Start-CaptureServer" nocase
		$StringToBase64 = "StringToBase64 " nocase
		$TexttoExe_1 = "TexttoExe " nocase
		$TexttoExe_2 = "Executable written to file "
    condition:
        any of them
}