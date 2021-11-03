rule MALW_PirateStealerJSObfuscate {
   meta:
      description = "PirateStealer obfuscated with javascript-obfuscate, packed with nexe. Automatically generated"
      author = "skyeto"
      reference = "piratestealer"
      date = "2021-11-03"
      hash1 = "38aeb8ae620cb833388c25b8ee5f5170d8290642d581dd577c5512a01035f5d7"
   strings:
      $x1 = ":detective:\\x20Successfull\\x20inject" ascii
      $s2 = "c:\\users\\vssadministrator\\.nexe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      1 of ($x*) and all of them
}

