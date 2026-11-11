"""issue-certificate-validity-exceeds-ca-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "issue-certificate-validity-exceeds-ca-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """IssueCertificate with a validity beyond the issuing CA's own validity fails with
    ValidationException and leaves the CA ACTIVE; a validity that fits is issued."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    # Activate with a short (90-day) CA certificate validity so that a
    # deliberately longer leaf-certificate request unambiguously overruns it.
    _activate_root_ca(ctx, ca_arn, ca_validity_days=90)

    leaf_csr = _scratch_leaf_csr(ctx)

    refusal = _error(
        lambda: acmpca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=leaf_csr,
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn="arn:aws:acm-pca:::template/EndEntityCertificate/V1",
            Validity={"Value": 365, "Type": "DAYS"},
        ),
        what="IssueCertificate with a 365-day leaf validity against a 90-day CA",
    )
    assert refusal == (
        "ValidationException",
        "The certificate validity specified exceeds the certificate authority validity.",
    ), refusal

    status = _status(ctx, ca_arn)
    assert status == "ACTIVE", f"expected CA status ACTIVE after the rejected issuance, got {status!r}"

    # Positive control: a validity within the CA's remaining validity is accepted.
    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=leaf_csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/EndEntityCertificate/V1",
        Validity={"Value": 30, "Type": "DAYS"},
    )
    cert_arn = issue_resp["CertificateArn"]
    cert_pem = _poll_until(
        lambda: _try_get_certificate(ctx, ca_arn, cert_arn), lambda v: v is not None, timeout_s=60
    )
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"positive-control certificate {cert_arn} did not come back as a PEM certificate: {cert_pem!r}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn: Callable[[], Any], *, what: str):
    """Return fn()'s ClientError (Code, Message); raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"{what} was ACCEPTED rather than refused; the call returned {resp!r}")


def _status(ctx, ca_arn: str) -> str:
    acmpca = ctx.client("acm-pca")
    return acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]


def _try_get_certificate(ctx, ca_arn: str, cert_arn: str):
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    try:
        return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "RequestInProgressException":
            return None
        raise


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


def _activate_root_ca(ctx, ca_arn: str, ca_validity_days: int = 365) -> None:
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
        Validity={"Value": ca_validity_days, "Type": "DAYS"},
    )
    cert_arn = issue_resp["CertificateArn"]
    cert_pem = _poll_until(
        lambda: _try_get_certificate(ctx, ca_arn, cert_arn), lambda v: v is not None, timeout_s=60
    )
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=cert_pem.encode("utf-8")
    )
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "ACTIVE", timeout_s=60)


def _scratch_leaf_csr(ctx) -> bytes:
    """Harvest a valid PKCS#10 CSR from a throwaway CA, avoiding client-side CSR generation.
    EndEntityCertificate ignores CA extensions the CSR requests, so it suits a leaf."""
    acmpca = ctx.client("acm-pca")
    scratch_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, scratch_arn))
    from botocore.exceptions import ClientError

    def _get_csr():
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=scratch_arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    csr = _poll_until(_get_csr, lambda v: v is not None, timeout_s=60)
    return csr.encode("utf-8")


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
