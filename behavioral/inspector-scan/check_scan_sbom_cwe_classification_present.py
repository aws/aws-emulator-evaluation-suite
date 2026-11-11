"""scan-sbom-cwe-classification-present."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-cwe-classification-present"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The Log4Shell finding carries its well-known CWE classification (CWE-502,
    Deserialization of Untrusted Data) alongside the CVE id, not an empty/omitted
    classification list."""
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

    cwes = vuln.get("cwes", [])
    import json
    assert cwes, json.dumps(vuln)[:400]
    assert 502 in cwes, f"expected CWE-502 (Deserialization of Untrusted Data) in {cwes}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
