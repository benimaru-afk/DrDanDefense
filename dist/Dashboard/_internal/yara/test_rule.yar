rule Test_Mimikatz_Strings
{
    meta:
        description = "Test rule - detects simulated Mimikatz-like strings"
        author      = "test"
        date        = "2026-05-01"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii
        $s2 = "lsadump::sam" ascii

    condition:
        any of them
}
