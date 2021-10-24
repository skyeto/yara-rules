rule MALW_PE_PirateStealer_1_4_5 {
    meta:
        description = "PirateStealer v1.4.5 malware"
        author = "skyeto"
        reference = "https://twitter.com/skyetothefox/status/1444442313367998467"
        date = "2021-10-24"
    strings:
        $x2 = "discord_desktop_core-" ascii wide
        $x3 = "file.replace" ascii wide
    condition:
        uint16(0) == 0x5a4d
        and all of them
}