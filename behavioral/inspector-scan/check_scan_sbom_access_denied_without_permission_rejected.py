"""scan-sbom-access-denied-without-permission-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "scan-sbom-access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector-scan"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ScanSbom from a user with no policies fails with AccessDeniedException and its
    exact message and returns no report, while the caller's own identity gets a report
    for the same SBOM."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    good_client = ctx.client("inspector-scan")

    user_name = ctx.unique_name("sim2real-inspscan-nopolicy-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    unprivileged_client = ctx.client(
        "inspector-scan",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    sbom = _minimal_sbom()

    # Freshly created access keys can take a few seconds to propagate; retry through
    # the transient authentication window until we reach a stable authorization
    # decision from the service itself.
    deadline = time.monotonic() + 30.0
    code = None
    message = None
    response = None
    while time.monotonic() < deadline:
        try:
            response = unprivileged_client.scan_sbom(sbom=sbom)
            code = None
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message")
            response = err.response
            if code in ("InvalidClientTokenId", "UnrecognizedClientException"):
                time.sleep(2.0)
                continue
            break

    assert code == "AccessDeniedException", (code, response)
    expected = (
        f"User: {user_arn} is not authorized to perform: inspector-scan:ScanSbom on resource: "
        f"arn:aws:inspector-scan:{ctx.region}:{ctx.account}:/scan/sbom because no identity-based "
        f"policy allows the inspector-scan:ScanSbom action"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"
    assert "sbom" not in response, "no vulnerability report should leak on a rejected call"

    good_response = good_client.scan_sbom(sbom=sbom)
    assert "sbom" in good_response, "positive control call with default credentials unexpectedly failed"


def _minimal_sbom() -> dict:
    return {
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
