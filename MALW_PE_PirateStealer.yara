rule MALW_PE_PirateStealer {
    meta:
        description = "PirateStealer malware"
        author = "skyeto"
        reference = "https://twitter.com/skyetothefox/status/1444442313367998467"
        date = "2021-10-13"
    strings:
        $x1 = "PirateStealerBTW" ascii wide
        $x2 = "6170692f776562686f6f6b73" ascii wide
    condition:
        uint16(0) == 0x5a4d
        and 1 of them
}