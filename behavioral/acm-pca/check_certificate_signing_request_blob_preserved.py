"""certificate-signing-request-blob-preserved."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "certificate-signing-request-blob-preserved"
GROUP = "representation"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated GetCertificateAuthorityCsr calls on one CA return byte-identical PEM CSRs,
    so the CSR is generated once at CA creation rather than regenerated (re-keyed) per call."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))

    csr_1 = _wait_for_csr(ctx, ca_arn)
    csr_2 = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    csr_3 = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]

    assert csr_1 == csr_2 == csr_3, "GetCertificateAuthorityCsr returned different content across calls"
    assert csr_1.startswith("-----BEGIN CERTIFICATE REQUEST-----"), (
        f"Csr does not look like a PEM-armored PKCS#10 request, got {csr_1[:64]!r}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _safe_delete_ca(ctx, ca_arn: str) -> None:
    """Wait out CREATING, disable if ACTIVE, then delete, retrying transient refusals.
    Raises if the CA is not gone within budget, since a private CA bills hourly."""
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 240
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _status(ctx, ca_arn)
        except ClientError:
            return  # no longer addressable; nothing left to bill
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
            except ClientError:
                pass
            time.sleep(2)
            continue
        try:
            acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(3)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: could not delete certificate authority {ca_arn} within "
        f"240s (last observed Status={last_status!r}). It is STILL BILLING. Delete it "
        f"manually: UpdateCertificateAuthority(Status='DISABLED') then "
        f"DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
