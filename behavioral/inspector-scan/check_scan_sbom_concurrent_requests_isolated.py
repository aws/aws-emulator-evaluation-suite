"""scan-sbom-concurrent-requests-isolated."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "scan-sbom-concurrent-requests-isolated"
GROUP = "concurrency"
SERVICES = ["inspector-scan"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent ScanSbom requests stay isolated: each response names its own unique
    component, only the SBOM carrying log4j-core reports CVE-2021-44228, and no clean
    request picks it up."""
    client = ctx.client("inspector-scan")
    worker_count = 6
    vulnerable_index = 3

    def build_sbom(i: int) -> dict:
        if i == vulnerable_index:
            component = {
                "bom-ref": "comp-target",
                "type": "library",
                "name": "log4j-core",
                "version": "2.12.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1",
            }
        else:
            marker = f"{uuid.uuid4().hex[:10]}-slot{i}"
            component = {
                "bom-ref": "comp-target",
                "type": "library",
                "name": f"sim2real-marker-{marker}",
                "version": "0.0.1",
                "purl": f"pkg:generic/sim2real-marker-vendor/sim2real-marker-{marker}@0.0.1",
            }
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "components": [component],
        }, component["name"]

    jobs = [build_sbom(i) for i in range(worker_count)]

    def call(job):
        sbom, expected_name = job
        report = client.scan_sbom(sbom=sbom, outputFormat="CYCLONE_DX_1_5")["sbom"]
        return expected_name, report

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        results = list(pool.map(call, jobs))

    for i, (expected_name, report) in enumerate(results):
        component_names = {c.get("name") for c in report.get("components", [])}
        assert expected_name in component_names, (
            f"slot {i} expected its own component {expected_name!r} echoed back, "
            f"got {component_names} -- possible cross-request contamination"
        )
        vulns = report.get("vulnerabilities", []) or []
        if i == vulnerable_index:
            assert any(v.get("id") == "CVE-2021-44228" for v in vulns), (
                f"vulnerable slot {i} did not report CVE-2021-44228"
            )
        else:
            assert not any(v.get("id") == "CVE-2021-44228" for v in vulns), (
                f"clean slot {i} incorrectly picked up the other request's finding"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
