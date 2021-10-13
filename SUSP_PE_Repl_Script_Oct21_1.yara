rule SUSP_PE_Repl_Script_Oct21_1 {
    meta:
        description = "Detects executables with suspicious references to repl.it"
        author = "skyeto"
        reference = "https://twitter.com/skyetothefox/status/1444442313367998467"
        date = "2021-10-13"
    strings:
        $x1 = ".repl.co/" ascii wide
    condition:
        uint16(0) == 0x5a4d
        and 1 of them
}