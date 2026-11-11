"""scan-sbom-invalid-output-format-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-invalid-output-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector-scan"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ScanSbom with outputFormat 'NOT_A_REAL_OUTPUT_FORMAT' fails with
    ValidationException and the exact enum-constraint message and no report, while the
    same SBOM with a valid outputFormat succeeds."""
    client = ctx.client("inspector-scan")
    sbom = {
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

    bad_code, bad_response = _invoke(client, sbom, "NOT_A_REAL_OUTPUT_FORMAT")
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code}"
    m = bad_response["Error"].get("Message")
    assert m == (
        "1 validation error detected: Value 'NOT_A_REAL_OUTPUT_FORMAT' at 'outputFormat' failed to "
        "satisfy constraint: Member must satisfy enum value set: [INSPECTOR_ALT, CYCLONE_DX_1_5, INSPECTOR]"
    ), m
    assert "sbom" not in bad_response, "no vulnerability report should leak on a rejected call"

    good_code, good_response = _invoke(client, sbom, "CYCLONE_DX_1_5")
    assert good_code is None, f"positive control unexpectedly failed with {good_code}"
    assert "sbom" in good_response, f"expected 'sbom' key in response, got keys {list(good_response)}"


def _invoke(client, sbom_value, output_format):
    from botocore.exceptions import ClientError

    try:
        result = client.scan_sbom(sbom=sbom_value, outputFormat=output_format)
        return None, result
    except ClientError as err:
        return err.response["Error"]["Code"], err.response


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
