"""put-policy-duplicate-conflicting-principal-blocked."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-policy-duplicate-conflicting-principal-blocked"
GROUP = "negative-classes"
SERVICES = ["acm-pca"]

_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE_ARN = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPolicy granting acm-pca:DeleteCertificateAuthority, an action outside the resource-policy
    allow-list, is refused with InvalidPolicyException and attaches nothing, while the same
    statements with only allow-listed actions are accepted and stored as sent.

    Reference: https://docs.aws.amazon.com/privateca/latest/APIReference/API_PutPolicy.html
    Reference: https://docs.aws.amazon.com/privateca/latest/userguide/pca-rbp.html
    """
    acmpca = ctx.client("acm-pca")
    sts = ctx.client("sts")
    ca_arn, _csr = _create_active_root_ca(ctx)
    own_account = sts.get_caller_identity()["Account"]

    def _put_disallowed_action_policy() -> None:
        acmpca.put_policy(
            ResourceArn=ca_arn,
            Policy=_cross_account_policy_doc(
                ca_arn, own_account, extra_action="acm-pca:DeleteCertificateAuthority"
            ),
        )

    refusal = _error(_put_disallowed_action_policy)
    assert refusal == (
        "InvalidPolicyException",
        "InvalidPolicy: Input policy containing action that is not allowed for resource type "
        "acm-pca:CertificateAuthority",
    ), refusal

    no_policy = _error(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert no_policy == ("ResourceNotFoundException", "Could not find policy for specified resource."), (
        f"expected no policy attached after rejection, got {no_policy!r}"
    )

    acmpca.put_policy(ResourceArn=ca_arn, Policy=_cross_account_policy_doc(ca_arn, own_account))
    ctx.on_cleanup(lambda: _best_effort(lambda: acmpca.delete_policy(ResourceArn=ca_arn)))

    attached = json.loads(acmpca.get_policy(ResourceArn=ca_arn)["Policy"])
    statements = attached["Statement"]
    assert len(statements) == 2, f"expected 2 statements from the accepted policy, got {len(statements)}"
    principal = statements[0]["Principal"]["AWS"]
    principal_values = principal if isinstance(principal, list) else [principal]
    assert any(own_account in value for value in principal_values), (
        f"expected principal to reference account {own_account!r}, got {principal!r}"
    )
    stored_actions = {action for stmt in statements for action in _as_list(stmt["Action"])}
    assert "acm-pca:DeleteCertificateAuthority" not in stored_actions, (
        f"disallowed action must not be present on the accepted policy, got {stored_actions!r}"
    )
    expected_actions = {
        "acm-pca:DescribeCertificateAuthority",
        "acm-pca:GetCertificate",
        "acm-pca:GetCertificateAuthorityCertificate",
        "acm-pca:ListPermissions",
        "acm-pca:ListTags",
        "acm-pca:IssueCertificate",
    }
    assert stored_actions == expected_actions, f"expected {expected_actions!r}, got {stored_actions!r}"


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _cross_account_policy_doc(ca_arn: str, principal_account: str, extra_action: str | None = None) -> str:
    read_actions = [
        "acm-pca:DescribeCertificateAuthority",
        "acm-pca:GetCertificate",
        "acm-pca:GetCertificateAuthorityCertificate",
        "acm-pca:ListPermissions",
        "acm-pca:ListTags",
    ]
    if extra_action:
        # An action outside the documented resource-policy allow-list (pca-rbp.html).
        read_actions = [*read_actions, extra_action]
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ExampleStatementID",
                    "Effect": "Allow",
                    "Principal": {"AWS": principal_account},
                    "Action": read_actions,
                    "Resource": ca_arn,
                },
                {
                    "Sid": "ExampleStatementID2",
                    "Effect": "Allow",
                    "Principal": {"AWS": principal_account},
                    "Action": ["acm-pca:IssueCertificate"],
                    "Resource": ca_arn,
                    "Condition": {
                        "StringEquals": {"acm-pca:TemplateArn": _END_ENTITY_TEMPLATE_ARN}
                    },
                },
            ],
        }
    )


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return the ClientError's (Code, Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _get_csr_when_ready(ctx, ca_arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RequestInProgressException":
                raise
            if time.monotonic() > deadline:
                raise AssertionError("CSR never became available in time") from exc
            time.sleep(interval_s)


def _get_certificate_when_ready(ctx, ca_arn: str, cert_arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> dict:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RequestInProgressException":
                raise
            if time.monotonic() > deadline:
                raise AssertionError("certificate never became available in time") from exc
            time.sleep(interval_s)


def _create_active_root_ca(ctx, usage_mode: str = "GENERAL_PURPOSE") -> tuple[str, str]:
    """Create a ROOT CA, self-sign and import its certificate; return (ca_arn, csr) once ACTIVE."""
    acmpca = ctx.client("acm-pca")
    common_name = ctx.unique_name("sim2real-pca-")
    ca_arn = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
        },
        CertificateAuthorityType="ROOT",
        UsageMode=usage_mode,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CertificateAuthorityArn"]

    def _cleanup() -> None:
        try:
            acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"],
        lambda status: status == "PENDING_CERTIFICATE",
        timeout_s=60.0,
        interval_s=3.0,
    )

    csr = _get_csr_when_ready(ctx, ca_arn)
    root_cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr,
        TemplateArn=_ROOT_TEMPLATE_ARN,
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Type": "DAYS", "Value": 3650},
    )["CertificateArn"]
    root_cert = _get_certificate_when_ready(ctx, ca_arn, root_cert_arn)["Certificate"]
    acmpca.import_certificate_authority_certificate(CertificateAuthorityArn=ca_arn, Certificate=root_cert)

    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"],
        lambda status: status == "ACTIVE",
        timeout_s=60.0,
        interval_s=3.0,
    )
    return ca_arn, csr


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
