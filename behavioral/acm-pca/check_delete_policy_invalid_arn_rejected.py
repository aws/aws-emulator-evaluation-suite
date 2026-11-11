"""delete-policy-invalid-arn-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-policy-invalid-arn-rejected"
GROUP = "state-machine"
SERVICES = ["acm-pca"]

_MALFORMED_ARN_MESSAGE = (
    "1 validation error detected: Value at 'resourceArn' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: "
    r"arn:[\w+=/,.@-]+:acm-pca:[\w+=/,.@-]*:[0-9]*:[\w+=,.@-]+(/[\w+=,.@-]+)*"
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicy with a malformed ResourceArn fails with ValidationException without
    touching the attached policy; DeletePolicy on the real CA ARN then succeeds."""
    acmpca = ctx.client("acm-pca")

    # Positive control setup happens BEFORE the negative call: a real CA with a
    # real attached policy can have that policy deleted successfully, and its
    # presence lets the negative call's effect-absence be checked against a
    # real resource rather than against nothing. Use an Organizations-style
    # wildcard principal (scoped by PrincipalOrgID/PrincipalAccount
    # conditions) -- AWS Private CA validates that an AWS-account Principal
    # actually exists, so a synthetic 12-digit account id is rejected with
    # InvalidPolicyException. The StringNotEquals PrincipalAccount clause
    # matches AWS's own documented org-sharing policy shape (denies
    # intra-account bypass of the org condition).
    ca_arn = _create_root_ca(ctx)
    _register_ca_cleanup(ctx, ca_arn)
    _activate_root_ca(ctx, ca_arn)
    own_account_id = ctx.client("sts").get_caller_identity()["Account"]

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realacmpcashare",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["acm-pca:GetCertificate", "acm-pca:GetCertificateAuthorityCertificate"],
                "Resource": ca_arn,
                "Condition": {
                    "StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4z5"},
                    "StringNotEquals": {"aws:PrincipalAccount": own_account_id},
                },
            }
        ],
    }

    acmpca.put_policy(ResourceArn=ca_arn, Policy=json.dumps(policy_doc))
    live_policy = acmpca.get_policy(ResourceArn=ca_arn)["Policy"]
    assert _policy_matches(live_policy, policy_doc), f"policy not stored as put: {live_policy!r} vs {policy_doc!r}"

    code = _error_code(lambda: acmpca.delete_policy(ResourceArn="not-an-arn"))
    assert code == ("ValidationException", _MALFORMED_ARN_MESSAGE), f"expected ValidationException for malformed ARN, got {code!r}"

    # Effect absent: the malformed-ARN call left the real policy on the real CA untouched.
    live_policy_after = acmpca.get_policy(ResourceArn=ca_arn)["Policy"]
    assert _policy_matches(live_policy_after, policy_doc), (
        f"policy mutated by rejected call: {live_policy_after!r} vs {policy_doc!r}"
    )

    # Positive control: the identical operation with the correct ARN succeeds.
    acmpca.delete_policy(ResourceArn=ca_arn)
    code_after = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert code_after == ("ResourceNotFoundException", "Could not find policy for specified resource."), (
        f"expected ResourceNotFoundException after delete, got {code_after!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _policy_matches(actual_doc_str: str, expected_doc: dict) -> bool:
    """Compare policy documents on their semantic content, not exact byte
    equality -- AWS Private CA normalizes the Principal/Condition shape
    when it echoes a policy back via GetPolicy."""
    a = json.loads(actual_doc_str)["Statement"][0]
    e = expected_doc["Statement"][0]
    return (
        a.get("Sid") == e.get("Sid")
        and a.get("Effect") == e.get("Effect")
        and set(a.get("Action", [])) == set(e.get("Action", []))
        and a.get("Resource") == e.get("Resource")
    )


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


def _register_ca_cleanup(ctx, arn: str) -> None:
    acmpca = ctx.client("acm-pca")

    def _cleanup():
        try:
            status = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "ACTIVE":
            acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
            _wait_for_ca_status(ctx, arn, {"DISABLED"}, timeout_s=30)
            status = "DISABLED"
        if status != "DELETED":
            acmpca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)

    ctx.on_cleanup(_cleanup)


def _wait_for_ca_status(ctx, arn: str, statuses, timeout_s: float = 90.0, interval_s: float = 2.0) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if last in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"CA {arn} never reached {statuses}, last status={last}")


def _poll_get_csr(ctx, arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError("CSR never became available")


def _poll_get_certificate(ctx, ca_arn: str, cert_arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError("Certificate never became available")


def _activate_root_ca(ctx, arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    _wait_for_ca_status(ctx, arn, {"PENDING_CERTIFICATE"})
    csr_pem = _poll_get_csr(ctx, arn)
    cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    cert_pem = _poll_get_certificate(ctx, arn, cert_arn)
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=arn,
        Certificate=cert_pem.encode("ascii"),
    )
    _wait_for_ca_status(ctx, arn, {"ACTIVE"})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
