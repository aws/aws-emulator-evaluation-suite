"""scan-sbom-epss-and-cvss-ratings-present."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-epss-and-cvss-ratings-present"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The Log4Shell finding is enriched with both a CVSS rating and an EPSS
    exploit-probability rating (distinct scoring vendors), demonstrating real
    vulnerability-intelligence enrichment rather than a single stubbed score."""
    client = ctx.client("inspector-scan")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": [
            {
                "bom-ref": "comp-log4j",
                "type": "library",
                "name": "log4j-core",
                "version": "2.12.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1",
            }
        ],
    }

    report = client.scan_sbom(sbom=sbom, outputFormat="CYCLONE_DX_1_5")["sbom"]
    vulns = report.get("vulnerabilities", []) or []
    vuln = next((v for v in vulns if v.get("id") == "CVE-2021-44228"), None)
    assert vuln is not None, f"CVE-2021-44228 not found among {[v.get('id') for v in vulns]}"

    ratings = vuln.get("ratings", [])
    sources = {r.get("source", {}).get("name") for r in ratings}
    methods = {str(r.get("method", "")) for r in ratings}

    assert "EPSS" in sources, f"expected an EPSS rating source, got {sources}"
    assert any("CVSS" in m for m in methods), f"expected a CVSS rating method, got {methods}"

    # A stubbed pair of bare source/method labels with no numeric content would still
    # satisfy the two set-membership checks above, contradicting this check's own
    # purpose ("not a single stubbed score"): each vendor must carry its own real,
    # independently-ranged numeric score.
    epss_rating = next(r for r in ratings if r.get("source", {}).get("name") == "EPSS")
    epss_score = float(epss_rating["score"])
    assert 0.0 <= epss_score <= 1.0, (
        f"EPSS score is an exploit-probability in [0, 1], got {epss_score}"
    )

    cvss_rating = next(r for r in ratings if "CVSS" in str(r.get("method", "")))
    cvss_score = float(cvss_rating["score"])
    assert 0.0 <= cvss_score <= 10.0, (
        f"CVSS score is on a 0-10 scale, got {cvss_score}"
    )

    assert epss_score != cvss_score, (
        f"EPSS ({epss_score}) and CVSS ({cvss_score}) came out identical — "
        "looks like one stubbed score duplicated across vendors, not two independent ratings"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
