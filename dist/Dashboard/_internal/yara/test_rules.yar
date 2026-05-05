rule TestMalwareString
{
    meta:
        description = "Trips on a plain trigger string"

    strings:
        $trigger = "MALWARE_TEST_PAYLOAD" ascii

    condition:
        $trigger
}