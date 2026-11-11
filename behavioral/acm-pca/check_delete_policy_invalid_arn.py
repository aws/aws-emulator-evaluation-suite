"""delete-policy-invalid-arn."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-policy-invalid-arn"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]

_MALFORMED_ARN_MESSAGE = (
    "1 validation error detected: Value at 'resourceArn' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: "
    r"arn:[\w+=/,.@-]+:acm-pca:[\w+=/,.@-]*:[0-9]*:[\w+=,.@-]+(/[\w+=,.@-]+)*"
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicy with a malformed CA ARN fails with ValidationException and leaves the
    attached policy in place; DeletePolicy with the correct ARN then removes it."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    _activate_root_ca(ctx, ca_arn)

    principal_account = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = json.dumps(_build_policy(ca_arn, principal_account))
    acmpca.put_policy(ResourceArn=ca_arn, Policy=policy_doc)

    malformed_arn = "not-an-acm-pca-arn"
    code = _error_code(lambda: acmpca.delete_policy(ResourceArn=malformed_arn))
    assert code == ("ValidationException", _MALFORMED_ARN_MESSAGE), f"expected ValidationException for malformed ARN, got {code!r}"

    # (b) effect absent: the real policy on the real CA is unaffected.
    live_policy = acmpca.get_policy(ResourceArn=ca_arn)["Policy"]
    assert _policy_matches(live_policy, policy_doc), f"policy mutated by rejected call: {live_policy!r} vs {policy_doc!r}"

    # (c) positive control: DeletePolicy with the correct ARN removes it.
    acmpca.delete_policy(ResourceArn=ca_arn)
    code_after = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert code_after == ("ResourceNotFoundException", "Could not find policy for specified resource."), f"expected ResourceNotFoundException after delete, got {code_after!r}"


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _policy_matches(actual_doc_str: str, expected_doc_str: str) -> bool:
    """Compare policy documents on their semantic content, not exact byte
    equality -- AWS Private CA normalizes the Principal (e.g. to an ARN)
    when it echoes a policy back via GetPolicy."""
    a = json.loads(actual_doc_str)["Statement"][0]
    e = json.loads(expected_doc_str)["Statement"][0]
    return (
        a.get("Sid") == e.get("Sid")
        and a.get("Effect") == e.get("Effect")
        and set(a.get("Action", [])) == set(e.get("Action", []))
        and a.get("Resource") == e.get("Resource")
    )


def _status(ctx, ca_arn: str) -> str:
    acmpca = ctx.client("acm-pca")
    return acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]


def _build_policy(ca_arn: str, principal_account: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realShareReadOnly",
                "Effect": "Allow",
                "Principal": {"AWS": principal_account},
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


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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

