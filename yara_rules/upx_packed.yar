rule Suspicious_UPX_Packed_Executable
{
    meta:
        author = "geddzzy"
        description = "Detects executables packed with UPX, commonly used for malware packing"
        reference = "https://yara.readthedocs.io/en/stable/writingrules.html"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        $upx_exe = "UPX!" ascii

    condition:
        uint16(0) == 0x5A4D and  /* PE header signature */
        any of ($upx*) 
}
