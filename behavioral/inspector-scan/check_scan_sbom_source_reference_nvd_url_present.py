"""scan-sbom-source-reference-nvd-url-present."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-source-reference-nvd-url-present"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The Log4Shell finding's top-level `source` points at the canonical NVD detail
    page for that exact CVE id -- not a generic placeholder URL."""
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

    source = vuln.get("source", {})
    import json
    assert isinstance(source, dict) and source.get("name") == "NVD", json.dumps(vuln)[:400]
    assert source.get("url") == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", source


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
