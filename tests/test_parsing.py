import pytest

from anssi_cve.epss import parse_epss_response
from anssi_cve.feeds import bulletin_type, extract_anssi_id, extract_cves, json_url
from anssi_cve.mitre import parse_cve_record
from anssi_cve.severity import base_severity


@pytest.mark.parametrize(
    ("link", "expected"),
    [
        ("https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0101/", "Avis"),
        ("https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-0007/", "Alerte"),
        ("https://example.org/other/", "Inconnu"),
    ],
)
def test_bulletin_type(link, expected):
    assert bulletin_type(link) == expected


def test_extract_anssi_id():
    assert extract_anssi_id("https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-0007/") == (
        "CERTFR-2026-ALE-0007"
    )
    assert extract_anssi_id("https://example.org/") is None


def test_json_url_handles_trailing_slash():
    assert json_url("https://x/avis/A/") == "https://x/avis/A/json/"
    assert json_url("https://x/avis/A") == "https://x/avis/A/json/"


def test_extract_cves_deduplicates_and_validates(load_fixture):
    assert extract_cves(load_fixture("bulletin_0101.json")) == ["CVE-2026-1111", "CVE-2026-2222"]
    assert extract_cves(load_fixture("bulletin_0102.json")) == []
    assert extract_cves(None) == []


def test_parse_cve_record_cna(load_fixture):
    d = parse_cve_record(load_fixture("cve_cna_cvss.json"))
    assert d.cvss == 9.8
    assert d.severity == "CRITICAL"
    assert d.cwe == "CWE-787"
    assert d.description == "Remote code execution in OpenSSH server."
    assert d.vendor == "OpenBSD"
    assert d.product == "OpenSSH, OpenSSH Portable"
    assert d.versions == "9.6, 9.7, 9.6p1"


def test_parse_cve_record_falls_back_to_adp(load_fixture):
    d = parse_cve_record(load_fixture("cve_adp_only.json"))
    assert d.cvss == 5.3
    assert d.severity == "MEDIUM"  # computed, ADP gave no baseSeverity
    assert d.cwe == "CWE-400"
    assert d.vendor is None and d.product is None and d.versions is None


def test_parse_cve_record_empty():
    d = parse_cve_record(None)
    assert d.cvss is None and d.description is None


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (None, None),
        (0, "NONE"),
        (3.9, "LOW"),
        (4.0, "MEDIUM"),
        (6.9, "MEDIUM"),
        (7.0, "HIGH"),
        (8.9, "HIGH"),
        (9.0, "CRITICAL"),
        (10, "CRITICAL"),
    ],
)
def test_base_severity(score, expected):
    assert base_severity(score) == expected


def test_parse_epss(load_fixture):
    assert parse_epss_response(load_fixture("epss.json")) == {
        "CVE-2026-1111": 0.91234,
        "CVE-2026-2222": 0.00045,
    }
    assert parse_epss_response(None) == {}
