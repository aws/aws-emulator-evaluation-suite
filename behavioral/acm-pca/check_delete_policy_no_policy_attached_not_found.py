"""delete-policy-no-policy-attached-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-policy-no-policy-attached-not-found"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicy on a CA with no policy attached is a successful no-op, DeletePolicy on a
    nonexistent CA ARN raises ResourceNotFoundException, and an attached policy is removed by it."""
    pca = ctx.client("acm-pca")
    arn = _create_minimal_ca(ctx)
    _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE", "FAILED"}, timeout_s=90)

    # No policy has ever been attached to this freshly created CA -- DeletePolicy
    # must succeed as a no-op, not raise ResourceNotFoundException.
    pca.delete_policy(ResourceArn=arn)  # raises if the emulator wrongly 404s here

    # Contrast: a well-formed ARN pointing at a CA that was never created (random
    # UUID substituted for the resource id) DOES raise ResourceNotFoundException --
    # this is the "resource not found" case that the no-policy-attached case must
    # NOT be conflated with.
    bogus_arn = arn.rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000"
    code = _error_code(lambda: pca.delete_policy(ResourceArn=bogus_arn))
    assert code == ("ResourceNotFoundException", "Could not find specified CA"), f"expected ResourceNotFoundException, got {code}"

    # Positive control: attach a real policy, confirm it's there, then delete it.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = _policy_doc(arn, account_id)
    pca.put_policy(ResourceArn=arn, Policy=json.dumps(policy_doc))
    attached = json.loads(pca.get_policy(ResourceArn=arn)["Policy"])
    assert attached["Statement"][0]["Sid"] == policy_doc["Statement"][0]["Sid"], (
        f"expected Sid {policy_doc['Statement'][0]['Sid']!r}, got {attached['Statement'][0].get('Sid')!r}"
    )

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
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _create_minimal_ca(ctx) -> str:
    pca = ctx.client("acm-pca")
    resp = pca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")},
        },
        Tags=[{"Key": "sim2real-check", "Value": "delete-policy-no-policy-attached-not-found"}],
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
