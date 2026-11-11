"""scan-sbom-malformed-document-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-malformed-document-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector-scan"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ScanSbom with a bare JSON string as the sbom fails with ValidationException
    "Input SBOM failed validation: Invalid json" and no report, while a valid clean SBOM
    succeeds with all-zero counts."""
    client = ctx.client("inspector-scan")

    bad_code, bad_response = _invoke(client, "this-is-not-a-cyclonedx-sbom-just-a-string")
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code}"
    m = bad_response["Error"].get("Message")
    assert m == "Input SBOM failed validation: Invalid json", f"expected the invalid-json message, got {m!r}"
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
    report = good_response["sbom"]
    counts = report.get("vulnerability_count")
    assert counts is not None, f"expected a vulnerability_count summary on the well-formed SBOM, got {report}"
    assert all(v == 0 for v in counts.values()), (
        f"expected zero findings for the fictitious control package, got {counts}"
    )


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
