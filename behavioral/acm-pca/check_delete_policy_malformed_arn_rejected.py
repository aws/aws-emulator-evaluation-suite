"""delete-policy-malformed-arn-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-policy-malformed-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicy with a malformed resource ARN returns InvalidArnException,
    leaves the real CA's resource policy attached, while deleting it with the
    correctly-formed ARN succeeds as a positive control."""
    pca = ctx.client("acm-pca")
    arn = _create_minimal_ca(ctx)
    _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE", "FAILED"}, timeout_s=90)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = _policy_doc(arn, account_id)
    pca.put_policy(ResourceArn=arn, Policy=json.dumps(policy_doc))
    attached = json.loads(pca.get_policy(ResourceArn=arn)["Policy"])
    assert attached["Statement"][0]["Sid"] == policy_doc["Statement"][0]["Sid"], (
        f"policy not stored as put: {attached!r} vs {policy_doc!r}"
    )

    # Malformed: strip the "/<resource-id>" suffix so the ARN no longer matches
    # the acm-pca certificate-authority ARN pattern.
    malformed_arn = arn.rsplit("/", 1)[0]
    code = _error_code(lambda: pca.delete_policy(ResourceArn=malformed_arn))
    assert code == ("InvalidArnException", "Not a valid arn."), f"expected InvalidArnException, got {code}"

    # Effect absent: the real policy is still attached, unaffected.
    still_attached = json.loads(pca.get_policy(ResourceArn=arn)["Policy"])
    assert still_attached["Statement"][0]["Sid"] == policy_doc["Statement"][0]["Sid"], (
        f"policy mutated by rejected call: {still_attached!r} vs {policy_doc!r}"
    )

    # Positive control: the well-formed ARN deletes the policy successfully.
    pca.delete_policy(ResourceArn=arn)
    code_after = _error_code(lambda: pca.get_policy(ResourceArn=arn))
    assert code_after == ("ResourceNotFoundException", "Could not find policy for specified resource."), f"expected ResourceNotFoundException, got {code_after}"


def _policy_doc(ca_arn: str, principal_account: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealCrossAccountRead",
                "Effect": "Allow",
                "Principal": {"AWS": principal_account},
                "Action": [
                    "acm-pca:DescribeCertificateAuthority",
                    "acm-pca:GetCertificateAuthorityCertificate",
                    "acm-pca:ListPermissions",
                    "acm-pca:ListTags",
                ],
                "Resource": ca_arn,
            }
        ],
    }


def _error_code(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_minimal_ca(ctx) -> str:
    pca = ctx.client("acm-pca")
    resp = pca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")},
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, arn))
    return arn


def _safe_delete_ca(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    pca = ctx.client("acm-pca")
    try:
        pca.delete_certificate_authority(CertificateAuthorityArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_status(ctx, arn: str, target_statuses: set[str], timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"CA never reached one of {target_statuses}, last status was {last_status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
