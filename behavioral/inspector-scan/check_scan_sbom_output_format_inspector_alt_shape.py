"""scan-sbom-output-format-inspector-alt-shape."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-output-format-inspector-alt-shape"
GROUP = "representation"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """outputFormat=INSPECTOR_ALT returns a distinct alternate report shape from both
    CYCLONE_DX_1_5 and INSPECTOR, and still surfaces the known Log4Shell finding."""
    client = ctx.client("inspector-scan")
    sbom = _sbom([_log4j_component("comp-log4j")])

    cyclone = client.scan_sbom(sbom=sbom, outputFormat="CYCLONE_DX_1_5")["sbom"]
    inspector = client.scan_sbom(sbom=sbom, outputFormat="INSPECTOR")["sbom"]
    alt = client.scan_sbom(sbom=sbom, outputFormat="INSPECTOR_ALT")["sbom"]

    # INSPECTOR_ALT must not be indistinguishable from the raw CycloneDX document shape.
    assert alt.get("bomFormat") != "CycloneDX" or set(alt.keys()) != set(cyclone.keys()), (
        f"INSPECTOR_ALT looks like a raw CycloneDX document: bomFormat={alt.get('bomFormat')!r} "
        f"alt_keys={sorted(alt.keys())} cyclone_keys={sorted(cyclone.keys())}"
    )

    # INSPECTOR_ALT must also be distinguishable from the plain INSPECTOR shape: every
    # real-AWS INSPECTOR_ALT vulnerability node carries a vendorAdvisories field that no
    # INSPECTOR node carries (confirmed against real AWS, not assumed from the model --
    # the model types the whole report as an opaque document).
    alt_vulns = alt.get("vulnerabilities") or []
    inspector_vulns = inspector.get("vulnerabilities") or []
    assert alt_vulns, f"expected INSPECTOR_ALT to report vulnerabilities, got {alt}"
    assert inspector_vulns, f"expected INSPECTOR to report vulnerabilities, got {inspector}"
    missing_on_alt = [v.get("id") for v in alt_vulns if "vendorAdvisories" not in v]
    assert not missing_on_alt, f"expected vendorAdvisories on every INSPECTOR_ALT node, missing on {missing_on_alt}"
    leaking_on_inspector = [v.get("id") for v in inspector_vulns if "vendorAdvisories" in v]
    assert not leaking_on_inspector, f"expected no vendorAdvisories on INSPECTOR nodes, found on {leaking_on_inspector}"

    matches = _find_nodes_mentioning(alt, "CVE-2021-44228", require_key="severity")
    assert matches, f"no vulnerability node mentioning CVE-2021-44228 with a severity field found in {json.dumps(alt)[:2000]}"
    assert any(str(m.get("severity", "")).lower() == "critical" for m in matches), matches


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


def _find_nodes_mentioning(obj, needle: str, require_key: str | None = None) -> list[dict]:
    matches: list[dict] = []

    def walk(node):
        if isinstance(node, dict):
            if (require_key is None or require_key in node) and needle in json.dumps(node):
                matches.append(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(obj)
    return matches


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
