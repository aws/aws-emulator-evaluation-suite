"""issue-certificate-invalid-validity-period-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "issue-certificate-invalid-validity-period-rejected"
GROUP = "negative-classes"
SERVICES = ["acm-pca"]

_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_TOO_LONG_MESSAGE = (
    "The requested certificate validity exceeds the maximum allowed by the usage mode. Reduce "
    "the requested validity period to be equal to or less than that supported by the usage mode "
    "for this CA or use a CA with a different usage mode."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """IssueCertificate on a SHORT_LIVED_CERTIFICATE CA rejects a Validity beyond the
    documented 7-day maximum for that usage mode (ValidationException), rather than
    silently truncating it or accepting it, while a validity within range is honored.
    """
    acmpca = ctx.client("acm-pca")
    ca_arn, csr = _create_active_root_ca(ctx, usage_mode="SHORT_LIVED_CERTIFICATE")

    # Short-lived-certificate CAs may only issue certificates with a validity of at
    # most 7 days (https://docs.aws.amazon.com/privateca/latest/userguide/short-lived-certificates.html).
    # Requesting 30 days must be rejected, not truncated to 7 or silently accepted.
    def _issue_too_long() -> None:
        acmpca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr,
            SigningAlgorithm="SHA256WITHRSA",
            Validity={"Type": "DAYS", "Value": 30},
        )

    refusal = _error(_issue_too_long)
    assert refusal == ("ValidationException", _TOO_LONG_MESSAGE), refusal

    # The rejection is deterministic, not a transient fluke: repeating it fails the
    # same way, and since IssueCertificate validates synchronously before signing,
    # no CertificateArn was ever minted for the out-of-range request (nothing to
    # look up / no partial state to clean up).
    refusal_repeat = _error(_issue_too_long)
    assert refusal_repeat == ("ValidationException", _TOO_LONG_MESSAGE), refusal_repeat

    # Positive control: the same CA, same CSR, a validity AT the 7-day boundary succeeds.
    good_cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr,
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Type": "DAYS", "Value": 7},
    )["CertificateArn"]
    good_cert = _get_certificate_when_ready(ctx, ca_arn, good_cert_arn)["Certificate"]
    assert good_cert.startswith("-----BEGIN CERTIFICATE-----"), (
        f"expected a PEM certificate for the in-range (7-day) request, got {good_cert!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
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
    """Create a ROOT private CA, self-sign and import its certificate via the API-only
    activation flow documented at
    https://docs.aws.amazon.com/privateca/latest/userguide/JavaApi-ActivateRootCA.html,
    and return (ca_arn, csr) once the CA reports status ACTIVE.
    """
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
        Tags=[{"Key": "sim2real", "Value": "issue-certificate-invalid-validity-period-rejected"}],
    )["CertificateAuthorityArn"]

    def _cleanup() -> None:
        try:
            acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
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
