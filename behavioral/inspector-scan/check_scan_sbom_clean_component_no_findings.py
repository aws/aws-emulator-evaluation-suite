"""scan-sbom-clean-component-no-findings."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-clean-component-no-findings"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A fictitious, never-published package name/purl that cannot match any real
    vulnerability yields zero findings, and the severity-count metadata properties
    are omitted entirely rather than reported as zero."""
    client = ctx.client("inspector-scan")
    marker = uuid.uuid4().hex[:12]
    component = {
        "bom-ref": "comp-clean",
        "type": "library",
        "name": f"sim2real-nonexistent-pkg-{marker}",
        "version": "0.0.1",
        "purl": f"pkg:generic/sim2real-nonexistent-vendor-{marker}/sim2real-nonexistent-pkg-{marker}@0.0.1",
    }
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": [component],
    }

    resp = client.scan_sbom(sbom=sbom)
    report = resp["sbom"]

    vulns = report.get("vulnerabilities", []) or []
    assert vulns == [], f"expected no vulnerabilities for a fictitious package, got {vulns}"

    props = {p["name"]: p["value"] for p in report.get("metadata", {}).get("properties", [])}
    severity_keys = (
        "amazon:inspector:sbom_scanner:critical_vulnerabilities",
        "amazon:inspector:sbom_scanner:high_vulnerabilities",
        "amazon:inspector:sbom_scanner:medium_vulnerabilities",
        "amazon:inspector:sbom_scanner:low_vulnerabilities",
    )
    present = {k: props[k] for k in severity_keys if k in props}
    assert not present, (
        f"a clean scan should carry no severity-count properties at all "
        f"(real AWS omits the block entirely rather than zeroing it), got {present}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
