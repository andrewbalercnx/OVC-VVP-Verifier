"""Constants for vetter certification management.

Sprint 61: Schema SAIDs, extended schema detection, and code validation sets.
Sprint 62: GSMA governance credential schema SAID.
"""

# VetterCertification schema SAID
VETTER_CERT_SCHEMA_SAID = "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H"

# GSMA Governance Credential schema SAID (Sprint 62)
GSMA_GOVERNANCE_SCHEMA_SAID = "EIBowJmxx5hNWQlfXqGcbN0aP_RBuucMW6mle4tAN6TL"

# Known extended schema SAIDs (fail-closed fallback if schema lookup fails)
KNOWN_EXTENDED_SCHEMA_SAIDS: set[str] = {
    "EPknTwPpSZi379molapnuN4V5AyhCxz_6TLYdiVNWvbV",  # Extended Legal Entity
    "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g",  # Extended Brand
    "EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_",  # Extended TNAlloc
}

# Valid E.164 country calling codes (ITU-T E.164 assigned codes)
# Source: ITU-T Operational Bulletin
VALID_ECC_CODES: set[str] = {
    "1", "7",  # Zone 1-2
    "20", "27",  # Africa
    "30", "31", "32", "33", "34", "36", "39",  # Europe
    "40", "41", "43", "44", "45", "46", "47", "48", "49",  # Europe
    "51", "52", "53", "54", "55", "56", "57", "58",  # Americas
    "60", "61", "62", "63", "64", "65", "66",  # Asia/Oceania
    "81", "82", "84", "86",  # Asia
    "90", "91", "92", "93", "94", "95", "98",  # Asia
    "211", "212", "213", "216", "218",  # Africa
    "220", "221", "222", "223", "224", "225", "226", "227", "228", "229",
    "230", "231", "232", "233", "234", "235", "236", "237", "238", "239",
    "240", "241", "242", "243", "244", "245", "246", "247", "248", "249",
    "250", "251", "252", "253", "254", "255", "256", "257", "258", "260",
    "261", "262", "263", "264", "265", "266", "267", "268", "269",
    "290", "291", "297", "298", "299",
    "350", "351", "352", "353", "354", "355", "356", "357", "358", "359",
    "370", "371", "372", "373", "374", "375", "376", "377", "378", "380",
    "381", "382", "383", "385", "386", "387", "389",
    "420", "421", "423",
    "500", "501", "502", "503", "504", "505", "506", "507", "508", "509",
    "590", "591", "592", "593", "594", "595", "596", "597", "598", "599",
    "670", "672", "673", "674", "675", "676", "677", "678", "679",
    "680", "681", "682", "683", "685", "686", "687", "688", "689",
    "690", "691", "692",
    "850", "852", "853", "855", "856",
    "870", "878", "880", "881", "882", "883",
    "886",
    "960", "961", "962", "963", "964", "965", "966", "967", "968", "970",
    "971", "972", "973", "974", "975", "976", "977", "992", "993", "994",
    "995", "996", "998",
}

# Valid ISO 3166-1 alpha-3 country codes
VALID_JURISDICTION_CODES: set[str] = {
    "AFG", "ALB", "DZA", "ASM", "AND", "AGO", "AIA", "ATA", "ATG", "ARG",
    "ARM", "ABW", "AUS", "AUT", "AZE", "BHS", "BHR", "BGD", "BRB", "BLR",
    "BEL", "BLZ", "BEN", "BMU", "BTN", "BOL", "BES", "BIH", "BWA", "BVT",
    "BRA", "IOT", "BRN", "BGR", "BFA", "BDI", "CPV", "KHM", "CMR", "CAN",
    "CYM", "CAF", "TCD", "CHL", "CHN", "CXR", "CCK", "COL", "COM", "COG",
    "COD", "COK", "CRI", "CIV", "HRV", "CUB", "CUW", "CYP", "CZE", "DNK",
    "DJI", "DMA", "DOM", "ECU", "EGY", "SLV", "GNQ", "ERI", "EST", "SWZ",
    "ETH", "FLK", "FRO", "FJI", "FIN", "FRA", "GUF", "PYF", "ATF", "GAB",
    "GMB", "GEO", "DEU", "GHA", "GIB", "GRC", "GRL", "GRD", "GLP", "GUM",
    "GTM", "GGY", "GIN", "GNB", "GUY", "HTI", "HMD", "VAT", "HND", "HKG",
    "HUN", "ISL", "IND", "IDN", "IRN", "IRQ", "IRL", "IMN", "ISR", "ITA",
    "JAM", "JPN", "JEY", "JOR", "KAZ", "KEN", "KIR", "PRK", "KOR", "KWT",
    "KGZ", "LAO", "LVA", "LBN", "LSO", "LBR", "LBY", "LIE", "LTU", "LUX",
    "MAC", "MDG", "MWI", "MYS", "MDV", "MLI", "MLT", "MHL", "MTQ", "MRT",
    "MUS", "MYT", "MEX", "FSM", "MDA", "MCO", "MNG", "MNE", "MSR", "MAR",
    "MOZ", "MMR", "NAM", "NRU", "NPL", "NLD", "NCL", "NZL", "NIC", "NER",
    "NGA", "NIU", "NFK", "MKD", "MNP", "NOR", "OMN", "PAK", "PLW", "PSE",
    "PAN", "PNG", "PRY", "PER", "PHL", "PCN", "POL", "PRT", "PRI", "QAT",
    "REU", "ROU", "RUS", "RWA", "BLM", "SHN", "KNA", "LCA", "MAF", "SPM",
    "VCT", "WSM", "SMR", "STP", "SAU", "SEN", "SRB", "SYC", "SLE", "SGP",
    "SXM", "SVK", "SVN", "SLB", "SOM", "ZAF", "SGS", "SSD", "ESP", "LKA",
    "SDN", "SUR", "SJM", "SWE", "CHE", "SYR", "TWN", "TJK", "TZA", "THA",
    "TLS", "TGO", "TKL", "TON", "TTO", "TUN", "TUR", "TKM", "TCA", "TUV",
    "UGA", "UKR", "ARE", "GBR", "USA", "UMI", "URY", "UZB", "VUT", "VEN",
    "VNM", "VGB", "VIR", "WLF", "ESH", "YEM", "ZMB", "ZWE",
}
