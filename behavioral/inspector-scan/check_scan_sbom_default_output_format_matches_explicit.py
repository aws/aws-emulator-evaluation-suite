"""scan-sbom-default-output-format-matches-explicit."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-default-output-format-matches-explicit"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ScanSbom without outputFormat returns the INSPECTOR report: the same top-level
    keys as an explicit outputFormat=INSPECTOR call, including vulnerability_count."""
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

    default_report = client.scan_sbom(sbom=sbom)["sbom"]
    inspector_report = client.scan_sbom(sbom=sbom, outputFormat="INSPECTOR")["sbom"]

    # Omitting outputFormat resolves to the same proprietary INSPECTOR-shaped report
    # (not CycloneDX) -- verified by structural (top-level key) equivalence between
    # the implicit-default call and an explicit outputFormat=INSPECTOR call.
    assert set(default_report.keys()) == set(inspector_report.keys()), (default_report, inspector_report)
    assert "vulnerability_count" in default_report, default_report


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
