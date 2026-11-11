"""issue-certificate-on-disabled-ca-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "issue-certificate-on-disabled-ca-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """IssueCertificate on a DISABLED CA fails with InvalidStateException and issues nothing,
    and the same call succeeds once the CA is re-enabled to ACTIVE."""
    acmpca = ctx.client("acm-pca")
    arn = _create_root_ca(ctx)
    _activate_root_ca(ctx, arn)

    csr = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]

    # (a) Positive control: IssueCertificate on the still-ACTIVE CA succeeds,
    # before anything is broken.
    control_cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE_ARN,
        Validity={"Value": 30, "Type": "DAYS"},
    )["CertificateArn"]
    control_cert = _poll_until(
        lambda: _try_get_certificate(acmpca, arn, control_cert_arn),
        lambda c: c is not None,
        timeout_s=60,
        interval_s=2,
    )
    assert "BEGIN CERTIFICATE" in control_cert, f"control-issued cert malformed: {control_cert!r}"

    # Break exactly one thing: disable the CA.
    acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
    _poll_until(
        lambda: _describe_status(acmpca, arn),
        lambda status: status == "DISABLED",
        timeout_s=60,
        interval_s=2,
    )

    # (b) IssueCertificate on the DISABLED CA must be rejected.
    code = _error_code(
        lambda: acmpca.issue_certificate(
            CertificateAuthorityArn=arn,
            Csr=csr,
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn=_END_ENTITY_TEMPLATE_ARN,
            Validity={"Value": 30, "Type": "DAYS"},
        )
    )
    assert code == ("InvalidStateException", "The certificate authority is not in a valid state for issuing certificates"), f"REFUSAL={code!r}"

    # (c) Restore: re-enable the CA, then the identical IssueCertificate call
    # succeeds for real and produces a certificate distinct from the control.
    acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="ACTIVE")
    _poll_until(
        lambda: _describe_status(acmpca, arn),
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )
    cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE_ARN,
        Validity={"Value": 30, "Type": "DAYS"},
    )["CertificateArn"]
    cert = _poll_until(
        lambda: _try_get_certificate(acmpca, arn, cert_arn),
        lambda c: c is not None,
        timeout_s=60,
        interval_s=2,
    )
    assert "BEGIN CERTIFICATE" in cert, f"post-restore cert malformed: {cert!r}"
    # Empirically (confirmed on real AWS): reissuing from the identical CSR,
    # template and validity on the same CA is deterministic -- it returns the
    # same CertificateArn as the pre-break control rather than minting a new
    # serial, so the DISABLED interval did not silently issue a *second*
    # certificate under the same identity.
    assert cert_arn == control_cert_arn, (
        f"post-restore issuance returned a different certificate ARN "
        f"({cert_arn!r}) than the pre-break control ({control_cert_arn!r}) for an "
        f"identical CSR/template/validity"
    )


_ROOT_CA_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE_ARN = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


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


def _activate_root_ca(ctx, arn: str) -> None:
    """Self-issue and import a root CA certificate, driving PENDING_CERTIFICATE -> ACTIVE."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

