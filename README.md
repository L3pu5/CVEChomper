# CVEChomper
This is a lagomorphic way of grabbing CVE definitions using free open source API.

This backs onto the following API and provides a wrapper for it:
    https://www.cve-search.org/api/

### Useage:
    Chomper <CVE> <flags>

#### Flags:

    "M": "Modified"
    "P": "Published"
    "x": "access"
    "a": "assigner"
    "c": "capec"
    "t": "cvss-time"
    "v": "cvss-vector"
    "C": "cwe"
    "i": "id"
    "I": "impact"
    "l": "last-modified"
    "r": "references"
    "m": "refmap"
    "u": "summary"
    "p": "vulnerable_product"
    "f": "vulnerable_configuration"

### Todo:
    python port