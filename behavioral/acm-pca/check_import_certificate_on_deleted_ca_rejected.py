"""import-certificate-on-deleted-ca-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-certificate-on-deleted-ca-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportCertificateAuthorityCertificate on a DELETED CA fails with InvalidStateException
    and does not reactivate it, while the same import on a PENDING_CERTIFICATE CA succeeds."""
    acmpca = ctx.client("acm-pca")
    arn = _create_root_ca(ctx)
    original_cert = _activate_root_ca(ctx, arn)
    status = _describe_status(acmpca, arn)
    assert status == "ACTIVE", f"expected ACTIVE after activation, got {status!r}"

    # CAs must be DISABLED before they can be deleted; disable, then delete so the
    # CA lands in DELETED state.
    acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
    _poll_until(
        lambda: _describe_status(acmpca, arn),
        lambda status: status == "DISABLED",
        timeout_s=60,
        interval_s=2,
    )
    acmpca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)
    _poll_until(
        lambda: _describe_status(acmpca, arn),
        lambda status: status == "DELETED",
        timeout_s=60,
        interval_s=2,
    )

    # (a) Re-importing the CA's own (previously valid) certificate onto the now
    # DELETED CA must be rejected.
    refusal = _error(
        lambda: acmpca.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=original_cert)
    )
    assert refusal == (
        "InvalidStateException",
        "The certificate authority is in the DELETED state and must be restored to complete this action.",
    ), refusal

    # (b) The effect is absent: the CA is still DELETED (the rejected import did
    # not change anything).
    status = _describe_status(acmpca, arn)
    assert status == "DELETED", f"expected DELETED (rejected import must not change state), got {status!r}"

    # (c) Positive control: a freshly created CA (PENDING_CERTIFICATE, no
    # certificate imported yet, never deleted) really can have a certificate
    # imported.
    arn2 = _create_root_ca(ctx)
    status2 = _describe_status(acmpca, arn2)
    assert status2 == "PENDING_CERTIFICATE", f"expected fresh CA in PENDING_CERTIFICATE, got {status2!r}"
    csr2 = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=arn2)["Csr"]
    cert_arn2 = acmpca.issue_certificate(
        CertificateAuthorityArn=arn2,
        Csr=csr2,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_CA_TEMPLATE_ARN,
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    cert2 = _poll_until(
        lambda: _try_get_certificate(acmpca, arn2, cert_arn2),
        lambda c: c is not None,
        timeout_s=60,
        interval_s=2,
    )
    acmpca.import_certificate_authority_certificate(CertificateAuthorityArn=arn2, Certificate=cert2)
    _poll_until(
        lambda: _describe_status(acmpca, arn2),
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )



_ROOT_CA_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _describe_status(acmpca, arn: str) -> str:
    return acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    name = ctx.unique_name("sim2real-behav-pca-")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": name},
        },
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["CertificateAuthorityArn"]

    def _cleanup() -> None:
        try:
            status = _describe_status(acmpca, arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "DELETED":
            return
        if status == "ACTIVE":
            acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
            _poll_until(
                lambda: _describe_status(acmpca, arn),
                lambda s: s == "DISABLED",
                timeout_s=60,
                interval_s=2,
            )
        acmpca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: _describe_status(acmpca, arn),
        lambda status: status == "PENDING_CERTIFICATE",
        timeout_s=60,
        interval_s=2,
    )
    return arn


def _try_get_certificate(acmpca, ca_arn: str, cert_arn: str) -> str | None:
    try:
        return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "RequestInProgressException":
            return None
        raise


def _activate_root_ca(ctx, arn: str) -> str:
    """Self-issue and import a root CA certificate, driving PENDING_CERTIFICATE -> ACTIVE.
    Returns the certificate PEM that was imported."""
    acmpca = ctx.client("acm-pca")
    csr = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
    cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_CA_TEMPLATE_ARN,
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    certificate = _poll_until(
        lambda: _try_get_certificate(acmpca, arn, cert_arn),
        lambda cert: cert is not None,
        timeout_s=60,
        interval_s=2,
    )
    acmpca.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=certificate)
    _poll_until(
        lambda: _describe_status(acmpca, arn),
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )
    return certificate


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)



