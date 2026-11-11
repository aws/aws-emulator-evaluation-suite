"""concurrent-delete-policy-race-conflict."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-policy-race-conflict"
GROUP = "concurrency"
SERVICES = ["acm-pca"]


_NO_POLICY_MESSAGE = "Could not find policy for specified resource."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent DeletePolicy calls on one CA both succeed (delete-if-exists, no
    ConcurrentModificationException) and GetPolicy then returns ResourceNotFoundException."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"})

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = _sample_policy(ca_arn, account_id)
    acmpca.put_policy(ResourceArn=ca_arn, Policy=policy_doc)
    landed = json.loads(acmpca.get_policy(ResourceArn=ca_arn)["Policy"])
    submitted = json.loads(policy_doc)
    assert landed["Statement"][0]["Sid"] == submitted["Statement"][0]["Sid"], (
        f"expected Sid {submitted['Statement'][0]['Sid']!r}, got {landed['Statement'][0].get('Sid')!r}"
    )
    assert landed["Statement"][0]["Resource"] == ca_arn, (
        f"expected policy Resource {ca_arn!r}, got {landed['Statement'][0].get('Resource')!r}"
    )
    assert set(landed["Statement"][0]["Action"]) == set(submitted["Statement"][0]["Action"]), (
        f"expected Action set {set(submitted['Statement'][0]['Action'])!r}, "
        f"got {set(landed['Statement'][0].get('Action', []))!r}"
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(acmpca.delete_policy, ResourceArn=ca_arn)
        f2 = pool.submit(acmpca.delete_policy, ResourceArn=ca_arn)
        err1 = _future_error(f1)
        err2 = _future_error(f2)

    errors = [err1, err2]
    # DeletePolicy is delete-if-exists: racing it against itself produces no loser.
    assert errors == [None, None], f"expected both racing DeletePolicy calls to succeed, got {errors}"

    code, message = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == _NO_POLICY_MESSAGE, f"unexpected GetPolicy message: {message!r}"

    # Positive control: a non-racing put+delete still removes the policy.
    acmpca.put_policy(ResourceArn=ca_arn, Policy=policy_doc)
    acmpca.delete_policy(ResourceArn=ca_arn)
    control_code, control_message = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert control_code == "ResourceNotFoundException", (
        f"positive control: expected ResourceNotFoundException, got {control_code!r}"
    )
    assert control_message == _NO_POLICY_MESSAGE, (
        f"positive control: unexpected GetPolicy message: {control_message!r}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("call succeeded; expected a ClientError")


def _future_error(future) -> str | None:
    try:
        future.result()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _sample_policy(ca_arn: str, account_id: str) -> str:
    # Mirrors AWS's own documented example of a private-CA resource policy:
    # https://docs.aws.amazon.com/privateca/latest/userguide/pca-rbp.html
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealCrossAccountReadOnly",
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": [
                        "acm-pca:DescribeCertificateAuthority",
                        "acm-pca:GetCertificate",
                        "acm-pca:GetCertificateAuthorityCertificate",
                        "acm-pca:ListPermissions",
                        "acm-pca:ListTags",
                    ],
                    "Resource": ca_arn,
                }
            ],
        }
    )


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    config = {
        "KeyAlgorithm": "RSA_2048",
        "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
    }
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration=config,
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ca_arn = resp["CertificateAuthorityArn"]

    def _cleanup() -> None:
        try:
            acmpca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return ca_arn


def _wait_for_ca_status(
    ctx, ca_arn: str, target_statuses: set[str], timeout_s: float = 90.0, interval_s: float = 3.0
) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"CA never reached {target_statuses}, last status was {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
