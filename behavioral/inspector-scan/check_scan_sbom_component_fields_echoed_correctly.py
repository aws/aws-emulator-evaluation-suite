"""scan-sbom-component-fields-echoed-correctly."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-component-fields-echoed-correctly"
GROUP = "data-plane"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The submitted component's identifying fields (name, version, purl) are passed
    through unchanged into the returned CycloneDX report -- the scan augments the SBOM
    with findings, it does not rewrite the caller's component metadata."""
    client = ctx.client("inspector-scan")
    marker = uuid.uuid4().hex[:12]
    name = f"sim2real-echo-pkg-{marker}"
    version = "9.9.9-sim2real"
    purl = f"pkg:generic/sim2real-echo-vendor-{marker}/{name}@{version}"
    component = {
        "bom-ref": "comp-echo",
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
    }
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": [component],
    }

    report = client.scan_sbom(sbom=sbom, outputFormat="CYCLONE_DX_1_5")["sbom"]
    import json
    returned = next((c for c in report.get("components", []) if c.get("purl") == purl), None)
    assert returned is not None, json.dumps(report)[:400]
    assert returned.get("name") == name, f"name: expected {name!r}, got {returned.get('name')!r}"
    assert returned.get("version") == version, (
        f"version: expected {version!r}, got {returned.get('version')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
