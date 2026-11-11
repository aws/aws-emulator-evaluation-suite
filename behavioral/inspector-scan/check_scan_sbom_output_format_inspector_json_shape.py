"""scan-sbom-output-format-inspector-json-shape."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-output-format-inspector-json-shape"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """outputFormat=INSPECTOR returns the Inspector-proprietary report shape (not raw
    CycloneDX) and still surfaces the known Log4Shell finding with critical severity."""
    client = ctx.client("inspector-scan")
    sbom = _sbom([_log4j_component("comp-log4j")])

    resp = client.scan_sbom(sbom=sbom, outputFormat="INSPECTOR")
    report = resp["sbom"]

    # The Inspector proprietary shape is not a raw CycloneDX document.
    assert report.get("bomFormat") != "CycloneDX", report

    vulns = report.get("vulnerabilities", []) or []
    vuln = next((v for v in vulns if v.get("id") == "CVE-2021-44228"), None)
    assert vuln is not None, f"CVE-2021-44228 not found among {[v.get('id') for v in vulns]}"
    assert str(vuln.get("severity", "")).lower() == "critical", vuln


def _sbom(components: list[dict]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": components,
    }


def _log4j_component(ref: str) -> dict:
    return {
        "bom-ref": ref,
        "type": "library",
        "name": "log4j-core",
        "version": "2.12.1",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1",
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
