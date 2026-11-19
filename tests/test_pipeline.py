"""End-to-end run with every HTTP call mocked, no network needed."""

import re

import feedparser
import pandas as pd
import responses

from anssi_cve import cli, pipeline
from anssi_cve.config import COLUMNS
from anssi_cve.http import build_session

BASE = "https://www.cert.ssi.gouv.fr/avis"


def _mock_apis(rsps, load_fixture):
    rsps.get(f"{BASE}/CERTFR-2026-AVI-0101/json/", json=load_fixture("bulletin_0101.json"))
    rsps.get(f"{BASE}/CERTFR-2026-AVI-0102/json/", json=load_fixture("bulletin_0102.json"))
    rsps.get(
        "https://cveawg.mitre.org/api/cve/CVE-2026-1111", json=load_fixture("cve_cna_cvss.json")
    )
    rsps.get(
        "https://cveawg.mitre.org/api/cve/CVE-2026-2222", json=load_fixture("cve_adp_only.json")
    )
    rsps.get(re.compile(r"https://api\.first\.org/data/v1/epss.*"), json=load_fixture("epss.json"))


def _fake_feed(load_fixture):
    parsed = feedparser.parse(str(load_fixture("feed_avis.xml")))
    return lambda url, limit=None: list(parsed.entries)[:limit] if limit else list(parsed.entries)


@responses.activate
def test_run_builds_expected_table(load_fixture, monkeypatch):
    _mock_apis(responses, load_fixture)
    monkeypatch.setattr(pipeline, "read_feed", _fake_feed(load_fixture))

    df = pipeline.run(build_session(retries=0), ["Avis"], workers=2)

    assert list(df.columns) == COLUMNS
    assert len(df) == 3  # 2 CVEs + 1 bulletin without CVE
    assert df.iloc[0]["ID ANSSI"] == "CERTFR-2026-AVI-0102"  # most recent first
    assert pd.isna(df.iloc[0]["CVE"])

    row = df[df["CVE"] == "CVE-2026-1111"].iloc[0]
    assert row["CVSS"] == 9.8
    assert row["Base Severity"] == "CRITICAL"
    assert row["CWE"] == "CWE-787"
    assert row["EPSS"] == 0.91234
    assert row["Type"] == "Avis"

    # each CVE fetched once, EPSS fetched in a single batch
    mitre_calls = [c for c in responses.calls if "cveawg" in c.request.url]
    epss_calls = [c for c in responses.calls if "first.org" in c.request.url]
    assert len(mitre_calls) == 2
    assert len(epss_calls) == 1


@responses.activate
def test_broken_bulletin_is_skipped(load_fixture, monkeypatch):
    _mock_apis(responses, load_fixture)
    responses.replace(responses.GET, f"{BASE}/CERTFR-2026-AVI-0101/json/", status=500)
    monkeypatch.setattr(pipeline, "read_feed", _fake_feed(load_fixture))

    df = pipeline.run(build_session(retries=0), ["Avis"], workers=2)
    assert df["ID ANSSI"].tolist() == ["CERTFR-2026-AVI-0102"]


@responses.activate
def test_cli_writes_csv(load_fixture, monkeypatch, tmp_path):
    _mock_apis(responses, load_fixture)
    monkeypatch.setattr(pipeline, "read_feed", _fake_feed(load_fixture))
    monkeypatch.setattr(cli, "build_session", lambda: build_session(retries=0))

    out = tmp_path / "out.csv"
    assert cli.main(["-o", str(out), "--feeds", "avis", "--min-cvss", "7"]) == 0
    written = pd.read_csv(out, encoding="utf-8-sig")
    assert written["CVE"].tolist() == ["CVE-2026-1111"]
