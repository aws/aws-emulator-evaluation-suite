"""delete-policy-after-ca-deleted-invalid-state."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-policy-after-ca-deleted-invalid-state"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicy on a DELETED CA succeeds (it does not gate on CA state) and really removes
    the policy: after RestoreCertificateAuthority, GetPolicy reports ResourceNotFoundException."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    _activate_root_ca(ctx, ca_arn)

    principal_account = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = json.dumps(_build_policy(ca_arn, principal_account))
    acmpca.put_policy(ResourceArn=ca_arn, Policy=policy_doc)
    fetched_policy = acmpca.get_policy(ResourceArn=ca_arn)["Policy"]
    assert _policy_matches(fetched_policy, policy_doc), f"expected GetPolicy to echo the put document, got {fetched_policy!r}"

    acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DISABLED", timeout_s=60)
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DELETED", timeout_s=60)

    acmpca.delete_policy(ResourceArn=ca_arn)

    # Restore the CA to confirm the policy was really removed.
    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    restored_status = _poll_until(lambda: _status(ctx, ca_arn), lambda s: s != "DELETED", timeout_s=60)
    assert restored_status == "DISABLED", f"expected restore to return to the pre-delete DISABLED state, got {restored_status!r}"
    code_after_restore = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert code_after_restore == ("ResourceNotFoundException", "Could not find policy for specified resource."), f"expected GetPolicy to still report the policy gone after restore, got {code_after_restore!r}"

    # DeletePolicy on a CA with no policy is a successful no-op.
    acmpca.delete_policy(ResourceArn=ca_arn)
    code_after_noop_delete = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert code_after_noop_delete == ("ResourceNotFoundException", "Could not find policy for specified resource."), f"expected GetPolicy to remain not-found after a no-op DeletePolicy, got {code_after_noop_delete!r}"


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
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
