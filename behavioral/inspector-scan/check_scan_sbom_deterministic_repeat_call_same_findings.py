"""scan-sbom-deterministic-repeat-call-same-findings."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-deterministic-repeat-call-same-findings"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two ScanSbom calls with an identical SBOM both report CVE-2021-44228 and agree on
    the full set of detected CVE ids, as the documented deterministic result requires."""
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

    first_ids = _cve_ids(client.scan_sbom(sbom=sbom)["sbom"])
    second_ids = _cve_ids(client.scan_sbom(sbom=sbom)["sbom"])

    assert "CVE-2021-44228" in first_ids, (
        f"expected CVE-2021-44228 in the first scan's findings, got {first_ids}"
    )
    assert "CVE-2021-44228" in second_ids, (
        f"expected CVE-2021-44228 in the second scan's findings, got {second_ids}"
    )
    assert first_ids == second_ids, (
        f"the same SBOM scanned twice in immediate succession produced different "
        f"CVE sets: {first_ids} vs {second_ids}"
    )


def _cve_ids(report: dict) -> set[str]:
    return {v.get("id") for v in report.get("vulnerabilities", []) or []}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
