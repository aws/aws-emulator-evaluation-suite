"""scan-sbom-partial-vulnerable-component-isolated."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-partial-vulnerable-component-isolated"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """When an SBOM mixes one vulnerable component with one clean component, findings
    must be attributed only to the vulnerable component's bom-ref -- a faithful matcher
    does not blanket-flag every component just because the SBOM contains a known CVE."""
    client = ctx.client("inspector-scan")
    marker = uuid.uuid4().hex[:12]
    vulnerable = {
        "bom-ref": "comp-vulnerable",
        "type": "library",
        "name": "log4j-core",
        "version": "2.12.1",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1",
    }
    clean = {
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
        "components": [vulnerable, clean],
    }

    resp = client.scan_sbom(sbom=sbom, outputFormat="CYCLONE_DX_1_5")
    report = resp["sbom"]
    vulns = report.get("vulnerabilities", []) or []
    assert vulns, "expected at least one finding for the vulnerable log4j-core component"

    # The API assigns its own bom-ref identifiers to echoed components (it does not
    # necessarily preserve the caller-supplied bom-ref), so resolve each component's
    # *actual* returned bom-ref by purl before checking `affects`.
    components = report.get("components", [])
    vulnerable_ref = next((c.get("bom-ref") for c in components if c.get("purl") == vulnerable["purl"]), None)
    clean_ref = next((c.get("bom-ref") for c in components if c.get("purl") == clean["purl"]), None)
    assert vulnerable_ref and clean_ref, components

    all_affected_refs: set[str] = set()
    for v in vulns:
        for a in v.get("affects", []):
            all_affected_refs.add(a.get("ref"))

    assert vulnerable_ref in all_affected_refs, (vulnerable_ref, all_affected_refs)
    assert clean_ref not in all_affected_refs, (
        f"clean component was incorrectly flagged as affected: {all_affected_refs}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
