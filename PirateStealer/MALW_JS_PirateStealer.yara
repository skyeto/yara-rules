rule MALW_JS_PirateStealerPKG {
    meta: 
        description = "PirateStealer Malware"
        author = "skyeto"
        reference = "https://twitter.com/skyetothefox/status/1444442313367998467"
        date = "2021-10-17"
    strings:
        $x1 = "discord_desktop_core" ascii wide
        $x2 = "raw.githubusercontent.com" ascii wide
    condition: 
        all of them
}