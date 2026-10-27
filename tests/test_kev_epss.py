from pipeline.epss import parse_epss
from pipeline.kev import parse_kev


def test_parse_kev_indexes_by_uppercased_cve():
    data = {
        "vulnerabilities": [
            {"cveID": "cve-2021-44228", "vendorProject": "Apache", "product": "Log4j"},
            {"cveID": "CVE-2023-1111", "vendorProject": "X", "product": "Y"},
            {"product": "no cve id -> skipped"},
        ]
    }
    kev = parse_kev(data)
    assert set(kev) == {"CVE-2021-44228", "CVE-2023-1111"}
    assert kev["CVE-2021-44228"]["vendor"] == "Apache"


def test_parse_epss_floats_and_skips_bad():
    payload = {
        "data": [
            {"cve": "CVE-2021-44228", "epss": "0.97456"},
            {"cve": "cve-2022-0001", "epss": "0.01"},
            {"cve": "CVE-BAD", "epss": "not-a-number"},
        ]
    }
    scores = parse_epss(payload)
    assert scores["CVE-2021-44228"] == 0.97456
    assert scores["CVE-2022-0001"] == 0.01
    assert "CVE-BAD" not in scores
