rule MALW_PE_PirateStealer_Variant.Baba {
    meta:
        description = "PirateStealer Variant, Skidded"
        author = "bytixoh"
        reference = "https://gist.github.com/bytixo/599938a8dbbe62a57c2d5c911dd5b87e"
        date = "2021-10-25"
    strings:
        $x2 = "TerminationAgainst/inject" ascii wide
        $x3 = "file.replace" ascii wide
    condition:
        uint16(0) == 0x5a4d
        and all of them
}