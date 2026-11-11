"""scan-sbom-component-count-scales-within-limit."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-component-count-scales-within-limit"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ScanSbom echoes every component of a large SBOM (under the 5,000 limit) and still
    attributes the vulnerabilities of the one seeded log4j-core 2.12.1 component to it
    alone, so scale neither truncates nor disables matching."""
    client = ctx.client("inspector-scan")
    component_count = 150
    log4j_purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1"
    components = [
        {
            "bom-ref": "comp-log4j",
            "type": "library",
            "name": "log4j-core",
            "version": "2.12.1",
            "purl": log4j_purl,
        }
    ]
    for i in range(component_count - 1):
        marker = uuid.uuid4().hex[:10]
        components.append(
            {
                "bom-ref": f"comp-{i}",
                "type": "library",
                "name": f"sim2real-bulk-pkg-{marker}",
                "version": "0.0.1",
                "purl": f"pkg:generic/sim2real-bulk-vendor-{marker}/sim2real-bulk-pkg-{marker}@0.0.1",
            }
        )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": components,
    }

    report = client.scan_sbom(sbom=sbom, outputFormat="CYCLONE_DX_1_5")["sbom"]
    returned_components = report.get("components", [])
    assert len(returned_components) == component_count, (
        f"got {len(returned_components)} expected {component_count}"
    )

    vulns = report.get("vulnerabilities", []) or []
    log4j_vulns = [v for v in vulns if v.get("id") == "CVE-2021-44228"]
    assert log4j_vulns, (
        f"CVE-2021-44228 not found among {component_count} components "
        f"(ids present: {[v.get('id') for v in vulns]})"
    )

    # The API assigns its own bom-ref identifiers to echoed components (it does not
    # necessarily preserve the caller-supplied bom-ref), so resolve the vulnerable
    # component's *actual* returned bom-ref by purl before checking `affects`.
    log4j_ref = next((c.get("bom-ref") for c in returned_components if c.get("purl") == log4j_purl), None)
    assert log4j_ref is not None, returned_components
    log4j_affected_refs = {a.get("ref") for v in log4j_vulns for a in v.get("affects", [])}
    assert log4j_ref in log4j_affected_refs, (log4j_ref, log4j_affected_refs)

    clean_refs = {c.get("bom-ref") for c in returned_components if c.get("purl") != log4j_purl}
    all_affected_refs = {a.get("ref") for v in vulns for a in v.get("affects", [])}
    misattributed = clean_refs & all_affected_refs
    assert not misattributed, f"clean components incorrectly flagged as affected: {misattributed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
