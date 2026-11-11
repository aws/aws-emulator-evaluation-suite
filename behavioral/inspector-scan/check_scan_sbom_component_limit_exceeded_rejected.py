"""scan-sbom-component-limit-exceeded-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-component-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector-scan"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ScanSbom rejects an SBOM of 5,001 components with ValidationException "Input SBOM
    failed validation: Max number of components exceeded (5000)" and no report, while
    exactly 5,000 components succeed."""
    client = ctx.client("inspector-scan")

    def make_components(n: int) -> list[dict]:
        return [
            {
                "bom-ref": f"comp-{i}",
                "type": "library",
                "name": f"sim2real-limit-pkg-{i}",
                "version": "1.0.0",
                "purl": f"pkg:generic/sim2real-limit-vendor/sim2real-limit-pkg-{i}@1.0.0",
            }
            for i in range(n)
        ]

    over_limit_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": make_components(5001),
    }
    bad_code, bad_response = _invoke(client, over_limit_sbom)
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code}"
    m = bad_response["Error"].get("Message")
    assert m == "Input SBOM failed validation: Max number of components exceeded (5000)", m
    assert "sbom" not in bad_response, "no vulnerability report should leak on a rejected call"

    at_limit_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": make_components(5000),
    }
    good_code, good_response = _invoke(client, at_limit_sbom)
    assert good_code is None, f"positive control unexpectedly failed with {good_code}"
    assert "sbom" in good_response


def _invoke(client, sbom_value):
    from botocore.exceptions import ClientError

    try:
        result = client.scan_sbom(sbom=sbom_value)
        return None, result
    except ClientError as err:
        return err.response["Error"]["Code"], err.response


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
