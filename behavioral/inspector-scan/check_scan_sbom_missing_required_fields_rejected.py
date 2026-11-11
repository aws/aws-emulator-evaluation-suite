"""scan-sbom-missing-required-fields-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-missing-required-fields-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector-scan"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ScanSbom with valid JSON lacking bomFormat/specVersion/components fails with
    ValidationException 'Input SBOM failed validation: Invalid value for "bomFormat"'
    and no report; a complete SBOM succeeds."""
    client = ctx.client("inspector-scan")

    bad_code, bad_response = _invoke(client, {})
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code}"
    m = bad_response["Error"].get("Message")
    assert m == 'Input SBOM failed validation: Invalid value for "bomFormat"', m
    assert "sbom" not in bad_response, "no vulnerability report should leak on a rejected call"

    good_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": [
            {
                "bom-ref": "comp-clean",
                "type": "library",
                "name": "sim2real-control-pkg",
                "version": "1.0.0",
                "purl": "pkg:generic/sim2real-control-vendor/sim2real-control-pkg@1.0.0",
            }
        ],
    }
    good_code, good_response = _invoke(client, good_sbom)
    assert good_code is None, f"positive control unexpectedly failed with {good_code}"
    assert "sbom" in good_response, f"positive control produced no report: {good_response}"


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
