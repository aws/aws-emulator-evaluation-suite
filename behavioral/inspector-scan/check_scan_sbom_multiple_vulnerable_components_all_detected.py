"""scan-sbom-multiple-vulnerable-components-all-detected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-multiple-vulnerable-components-all-detected"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ScanSbom attributes findings per component: log4j-core 2.12.1 and
    commons-collections 3.2.1 are each named in the affects list of their own CVE
    findings, and the commons component is absent from log4j-only findings."""
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
            },
            {
                "bom-ref": "comp-commons",
                "type": "library",
                "name": "commons-collections",
                "version": "3.2.1",
                "purl": "pkg:maven/commons-collections/commons-collections@3.2.1",
            },
        ],
    }

    report = client.scan_sbom(sbom=sbom, outputFormat="CYCLONE_DX_1_5")["sbom"]
    vulns = report.get("vulnerabilities", []) or []
    assert vulns, "expected findings for two independently-vulnerable components"

    # The API assigns its own bom-ref identifiers to echoed components (it does not
    # necessarily preserve the caller-supplied bom-ref), so resolve each component's
    # *actual* returned bom-ref by purl before checking `affects`.
    components = report.get("components", [])
    log4j_purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1"
    commons_purl = "pkg:maven/commons-collections/commons-collections@3.2.1"
    log4j_ref = next((c.get("bom-ref") for c in components if c.get("purl") == log4j_purl), None)
    commons_ref = next((c.get("bom-ref") for c in components if c.get("purl") == commons_purl), None)
    assert log4j_ref and commons_ref, components

    log4j_vulns = [v for v in vulns if v.get("id") == "CVE-2021-44228"]
    assert log4j_vulns, f"CVE-2021-44228 not found among {[v.get('id') for v in vulns]}"
    log4j_refs = {a.get("ref") for v in log4j_vulns for a in v.get("affects", [])}
    assert log4j_ref in log4j_refs, (log4j_ref, log4j_refs)

    commons_refs = {
        a.get("ref")
        for v in vulns
        for a in v.get("affects", [])
        if a.get("ref") == commons_ref
    }
    assert commons_ref in commons_refs, (
        f"expected at least one finding attributed to commons-collections 3.2.1, "
        f"got vulnerability ids {[v.get('id') for v in vulns]}"
    )
    # The log4j-specific CVE must not be mis-attributed to the unrelated component.
    log4j_only_refs = {a.get("ref") for v in log4j_vulns for a in v.get("affects", [])}
    assert commons_ref not in log4j_only_refs, (
        f"CVE-2021-44228 (log4j-only) was incorrectly attributed to commons-collections: {log4j_only_refs}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
