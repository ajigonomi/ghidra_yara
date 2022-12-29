rule Hermetic_Rule {
    meta:
        author = "ajigonomi"
        create_date = "2022-12-29"
        modified_date = ""
        hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
        hash2 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
        hash3 = "2c10b2ec0b995b88c27d141d6f7b14d6b8177c52818687e4ff8e6ecf53adf5bf"
        hash4 = "3c557727953a8f6b4788984464fb77741b821991acbf5e746aebdd02615b1767"
        hash5 = "a64c3e0522fad787b95bfb6a30c3aed1b5786e69e88e023c062ec7e5cebf4d3e"
        hash6 = "06086c1da4590dcc7f1e10a6be3431e1166286a9e7761f2de9de79d7fda9c397"
        description = ""
    strings:
        $C_Cash = { 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 43 00 72 00 61 00 73 00 68 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 00 00  }
    condition:
        uint16(0) == 0x5a4d and // MZ
        uint32(uint32(0x3c)) == 0x00004550 and //PE
        all of them // REPLACE HERE
}