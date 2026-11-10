// Demonstration only. Detects a harmless RTF file header.
rule Demo_RTF_Header {
    strings:
        $header = "{\\rtf1"
    condition:
        $header at 0
}
