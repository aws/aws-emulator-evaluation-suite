"""put-policy-disallowed-action-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-policy-disallowed-action-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPolicy granting a non-shareable action (DeleteCertificateAuthority) fails with
    InvalidPolicyException and stores no policy; a policy granting only shareable actions
    is accepted."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    _activate_root_ca(ctx, ca_arn)

    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bad_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realDisallowedAction",
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": ["acm-pca:DeleteCertificateAuthority"],
                    "Resource": ca_arn,
                }
            ],
        }
    )
    refusal = _error(lambda: acmpca.put_policy(ResourceArn=ca_arn, Policy=bad_policy))
    assert refusal == (
        "InvalidPolicyException",
        "InvalidPolicy: Input policy containing action that is not allowed for resource type "
        "acm-pca:CertificateAuthority",
    ), refusal

    # (b) effect absent: no policy was persisted on the CA.
    absent = _error(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert absent == ("ResourceNotFoundException", "Could not find policy for specified resource."), (
        f"expected no policy persisted after the rejection, got {absent!r}"
    )

    # (c) positive control: a policy restricted to supported, shareable
    # actions is accepted and retrievable.
    good_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realAllowedAction",
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": ["acm-pca:GetCertificate"],
                    "Resource": ca_arn,
                }
            ],
        }
    )
    acmpca.put_policy(ResourceArn=ca_arn, Policy=good_policy)
    stored = json.loads(acmpca.get_policy(ResourceArn=ca_arn)["Policy"])
    assert stored["Statement"][0]["Effect"] == "Allow", stored
    stored_action = stored["Statement"][0]["Action"]
    if isinstance(stored_action, str):
        stored_action = [stored_action]
    assert set(stored_action) == {"acm-pca:GetCertificate"}, stored_action


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn: Callable[[], Any]) -> tuple:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _status(ctx, ca_arn: str) -> str:
    acmpca = ctx.client("acm-pca")
    return acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    return resp["CertificateAuthorityArn"]


def _activate_root_ca(ctx, ca_arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    def _get_csr():
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    csr = _poll_until(_get_csr, lambda v: v is not None, timeout_s=60)
    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 365, "Type": "DAYS"},
    )
    cert_arn = issue_resp["CertificateArn"]

    def _get_cert():
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    cert_pem = _poll_until(_get_cert, lambda v: v is not None, timeout_s=60)
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=cert_pem.encode("utf-8")
    )
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "ACTIVE", timeout_s=60)


def _safe_delete_ca(ctx, ca_arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    try:
        status = _status(ctx, ca_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "ACTIVE":
        acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DISABLED", timeout_s=60)
    if status != "DELETED":
        acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
