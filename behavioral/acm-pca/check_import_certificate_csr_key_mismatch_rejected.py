"""import-certificate-csr-key-mismatch-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "import-certificate-csr-key-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Importing a valid self-signed certificate for another CA's key fails with
    CertificateMismatchException and leaves the CA PENDING_CERTIFICATE; a matching import works."""
    acmpca = ctx.client("acm-pca")

    ca_a = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_a))
    ca_b = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_b))

    csr_a = _wait_for_csr(ctx, ca_a)
    csr_b = _wait_for_csr(ctx, ca_b)

    # CA-B's self-signed certificate is well-formed but carries the wrong key for CA-A.
    cert_b_pem = _self_sign(ctx, ca_b, csr_b)

    refusal = _error(
        lambda: acmpca.import_certificate_authority_certificate(
            CertificateAuthorityArn=ca_a, Certificate=cert_b_pem.encode("utf-8")
        )
    )
    assert refusal == (
        "CertificateMismatchException",
        "The certificate subject contains a different subject than the CA certificate signing request.",
    ), refusal

    status_after_reject = _status(ctx, ca_a)
    assert status_after_reject == "PENDING_CERTIFICATE", (
        f"expected CA-A to remain PENDING_CERTIFICATE after the rejected import, "
        f"got {status_after_reject!r}"
    )

    # Positive control: CA-A's own self-signed certificate imports and activates it.
    cert_a_pem = _self_sign(ctx, ca_a, csr_a)
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_a, Certificate=cert_a_pem.encode("utf-8")
    )
    status = _poll_until(lambda: _status(ctx, ca_a), lambda s: s == "ACTIVE", timeout_s=60)
    assert status == "ACTIVE", f"expected CA-A to activate on the correct import, got {status!r}"


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn: Callable[[], Any]):
    """Return fn()'s ClientError (Code, Message); raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected the mismatched import to be rejected, but it SUCCEEDED and returned {result!r}")


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
        Tags=[{"Key": "sim2real", "Value": "csr-key-mismatch-rejected"}],
    )
    return resp["CertificateAuthorityArn"]


def _wait_for_csr(ctx, ca_arn: str) -> str:
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    def _get():
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    return _poll_until(_get, lambda v: v is not None, timeout_s=60)


def _self_sign(ctx, ca_arn: str, csr: str) -> str:
    """Issue a root certificate for the CA's own CSR, signed by the CA itself."""
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 365, "Type": "DAYS"},
    )
    cert_arn = issue_resp["CertificateArn"]

    def _get():
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    return _poll_until(_get, lambda v: v is not None, timeout_s=60)


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
