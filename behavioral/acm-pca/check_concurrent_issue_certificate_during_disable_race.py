"""concurrent-issue-certificate-during-disable-race."""
from __future__ import annotations

import threading
import time
from typing import Any

from behavioral_harness import tags

CHECK = "concurrent-issue-certificate-during-disable-race"
GROUP = "concurrency"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """IssueCertificate racing UpdateCertificateAuthority(DISABLED) on an ACTIVE CA is never
    ambiguous: a reported success yields a retrievable certificate, and a rejection is exactly
    InvalidStateException with no certificate created."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from botocore.exceptions import ClientError

    acmpca = ctx.client("acm-pca")
    ca_arn = _create_ca(ctx)
    _activate_root_ca(ctx, ca_arn)

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ctx.unique_name("sim2real-leaf-"))]))
        .sign(leaf_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    results = _race_issue_disable(acmpca, ClientError, ca_arn, csr_pem)

    issue_status, issue_val = results["issue"]
    if issue_status == "ok":
        cert_arn = issue_val
        cert_pem = _poll_get_certificate(ctx, ca_arn, cert_arn)
        assert cert_pem.startswith("-----BEGIN CERTIFICATE-----"), (
            f"IssueCertificate reported success ({cert_arn!r}) but GetCertificate did not return "
            f"a PEM-encoded certificate; got {cert_pem[:80]!r}"
        )
    else:
        assert issue_val == "InvalidStateException", (
            f"expected a rejected IssueCertificate racing UpdateCertificateAuthority(DISABLED) to "
            f"fail with InvalidStateException, got {issue_val!r}"
        )

    # The disable call may itself observe ConcurrentModificationException if it lands
    # while the CA is mid-signing; retry it (a plain, non-racing call) until it either
    # succeeds or the CA is confirmed already DISABLED, then verify the terminal state.
    disable_status, disable_val = results["disable"]
    if disable_status == "error":
        assert disable_val == "ConcurrentModificationException", (
            f"expected UpdateCertificateAuthority racing IssueCertificate to fail only with "
            f"ConcurrentModificationException if it fails at all, got {disable_val!r}"
        )
        _retry_disable(ctx, ca_arn)

    final_status = _wait_for_ca_status(ctx, ca_arn, {"DISABLED"})
    assert final_status == "DISABLED", f"expected the CA to converge to DISABLED, got {final_status!r}"


def _create_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-pca-")},
        },
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    return ca_arn


def _safe_delete_ca(ctx, ca_arn: str) -> None:
    """Delete the CA, disabling it first: ACM PCA refuses to delete an ACTIVE CA."""
    from botocore.exceptions import ClientError

    acmpca = ctx.client("acm-pca")
    try:
        status = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "DELETED":
        return
    if status == "ACTIVE":
        acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        _wait_for_ca_status(ctx, ca_arn, {"DISABLED"})
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)


def _wait_for_ca_status(ctx, ca_arn: str, target_statuses: set, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"CA never reached {target_statuses}, last status={last}")


def _poll_get_certificate(ctx, ca_arn: str, cert_arn: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    from botocore.exceptions import ClientError

    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "RequestInProgressException":
                raise
        time.sleep(interval_s)
    raise AssertionError("certificate never became available within timeout")


def _activate_root_ca(ctx, ca_arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"})
    csr = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 10, "Type": "YEARS"},
    )
    cert_arn = issue_resp["CertificateArn"]
    cert_pem = _poll_get_certificate(ctx, ca_arn, cert_arn)
    acmpca.import_certificate_authority_certificate(CertificateAuthorityArn=ca_arn, Certificate=cert_pem)
    _wait_for_ca_status(ctx, ca_arn, {"ACTIVE"})


def _race_issue_disable(acmpca, client_error_cls, ca_arn: str, csr_pem: bytes) -> dict[str, tuple[str, Any]]:
    barrier = threading.Barrier(2)
    results: dict[str, tuple[str, Any]] = {}

    def issue_call() -> None:
        barrier.wait()
        try:
            resp = acmpca.issue_certificate(
                CertificateAuthorityArn=ca_arn,
                Csr=csr_pem,
                SigningAlgorithm="SHA256WITHRSA",
                TemplateArn="arn:aws:acm-pca:::template/EndEntityCertificate/V1",
                Validity={"Value": 30, "Type": "DAYS"},
            )
            results["issue"] = ("ok", resp["CertificateArn"])
        except client_error_cls as e:
            results["issue"] = ("error", e.response["Error"]["Code"])

    def disable_call() -> None:
        barrier.wait()
        try:
            acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
            results["disable"] = ("ok", None)
        except client_error_cls as e:
            results["disable"] = ("error", e.response["Error"]["Code"])

    t1 = threading.Thread(target=issue_call)
    t2 = threading.Thread(target=disable_call)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return results


def _retry_disable(ctx, ca_arn: str, attempts: int = 10, interval_s: float = 2.0) -> None:
    from botocore.exceptions import ClientError

    acmpca = ctx.client("acm-pca")
    for _ in range(attempts):
        try:
            acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ConcurrentModificationException":
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError("could not settle CA into DISABLED after retrying past ConcurrentModificationException")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
