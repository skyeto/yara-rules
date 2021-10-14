rule SUSP_PE_GitHub_Oct21_1 {
    meta:
        description = "Detects executables with suspicious references to githubusercontent.com"
        author = "skyeto"
        date = "2021-10-14"
    strings:
        $x1 = "raw.githubusercontent.com" ascii wide
    condition:
        uint16(0) == 0x5a4d
        and 1 of them
}