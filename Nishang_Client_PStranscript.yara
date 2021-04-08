rule Nishang_Client_PStranscript
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the outputs or inputs to the powershell scripts in the Client section of the Nishang Framework.  It is designed to be ran against PowerShell Transcript Logs"
    strings:
		$Out_CHM_1 = "Out-CHM" nocase
		$Out_CHM_2 = "Payload too big for CHM! Try a smaller payload."
		$Out_Excel_1 = "Out-Excel" nocase
		$Out_Excel_2 = "Using the DDE technique for dir."
		$Out_Excel_3 = "Using auto-executable macro."
		$Out_Excel_4 = "RemainUnsafe selected. Not turning on Macro Security"
		$Out_HTA_1 = "Out-HTA" nocase
		$Out_HTA_2 = "HTA written to "
		$Out_JS_1 = "Out-JS" nocase
		$Out_JS_2 = "Weaponized JS file written to "
		$Out_Java_1 = "Out-Java" nocase
		$Out_Java_2 = "You chose not to self sign. Use your valid certificate to sign the JavaPS.jar manually."
		$Out_SCF_1 = "Out-SCF" nocase
		$Out_SCF_2 = "SCF file written to "
		$Out_SCT_1 = "Out-SCT" nocase
		$Out_SCT_2 = "Weaponized SCT file written to "
		$Out_SCT_3 = "Run the following command on the target:"
		$Out_SCT_4 = "/UpdateCheck.xml scrobj.dll"
		$Out_Shortcut_1 = "Out-Shortcut" nocase
		$Out_Shortcut_2 = "The Shortcut file has been written as "
		$Out_WebQuery_1 = "Out-WebQuery" nocase
		$Out_WebQuery_2 = "The Web Query file has been written as "
		$Out_Word_1 = "Out-Word" nocase
		$Out_Word_2 = "DDE Attack cannot have payload longer than 256 characters. Exiting..."
		$Out_Word_3 = "Payload too big for VBA! Try a smaller payload."
    condition:
        any of them
}