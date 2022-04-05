dosinfo = [
    ("MZ标志字段", 0x0, 4, "big"),
    ("e_lfanew字段", 0x3c, 4, "little"),
]

peinfo = [
    ("Signature字段", 0x0, 4, "big"),
    ("Machine字段", 0x4, 2, "little"),
    ("NumberofSections字段", 0x6, 2, "little"),
    ("TimedateStamp字段", 0x8, 4, "little"),
    ("SizeofOptionalHeader字段", 0x14, 2, "little"),
    ("Characteristics字段", 0x16, 2, "little"),
    ("Magic字段", 0x18, 2, "little"),
    ("ImageBase字段", 0x34, 4, "little"),
    ("SectionAlignment字段", 0x38, 4, "little"),
    ("FileAlignment字段", 0x3C, 4, "little"),
    ("SizeOfImage字段", 0x50, 4, "little"),
    ("SizeOfHeaders字段", 0x54, 4, "little"),
    ("NumberofRvaAndSize字段", 0x74, 4, "little"),
    ("DataDirectory_Export_Rva", 0x78, 4, "little"),
    ("DataDirectory_Export_Size", 0x7c, 4, "little"),
    ("DataDirectory_Import_Rva", 0x80, 4, "little"),
    ("DataDirectory_Import_Size", 0x84, 4, "little"),
]

sectioninfo = [
    ("SectionName", 0xf8, 8, "big"),
    ("VirtualSize", 0x100, 4, "little"),
    ("VirtualAddress", 0x104, 4, "little"),
    ("SizeOfRawData", 0x110, 4, "little"),
    ("PointerToRawData", 0x10c, 4, "little"),
    ("Characteristics", 0x11c, 4, "little"),
]

importtableinfo = [
    ("OriginalFirstThunk字段", 0x0, 4, "little"),
    ("TimeDateStamp字段", 0x4, 4, "little"),
    ("ForwarderChain字段", 0x8, 4, "little"),
    ("Name1字段", 0xc, 4, "little"),
    ("FirstThunk字段", 0x10, 4, "little"),
]

pedata = {

}

sectiondata = {

}

importtables = {

}