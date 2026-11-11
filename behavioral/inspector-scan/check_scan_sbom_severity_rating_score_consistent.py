"""scan-sbom-severity-rating-score-consistent."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-severity-rating-score-consistent"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The NVD CVSSv3 rating attached to the Log4Shell finding must be internally
    consistent: a numeric base score in the CVSS v3 'Critical' band (>= 9.0) must be
    paired with a 'critical' severity label, not a stubbed/mismatched pair."""
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

    cvss_ratings = [
        r
        for r in vuln.get("ratings", [])
        if r.get("source", {}).get("name") == "NVD" and "CVSS" in str(r.get("method", ""))
    ]
    assert cvss_ratings, f"no NVD CVSS rating present: {vuln.get('ratings')}"

    for rating in cvss_ratings:
        score = float(rating["score"])
        severity = str(rating.get("severity", "")).lower()
        if score >= 9.0:
            assert severity == "critical", f"score {score} should map to critical, got {severity!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
