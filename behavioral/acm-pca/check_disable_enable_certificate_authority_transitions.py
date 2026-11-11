"""disable-enable-certificate-authority-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disable-enable-certificate-authority-transitions"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateCertificateAuthority ACTIVE -> DISABLED -> ACTIVE shows on DescribeCertificateAuthority;
    IssueCertificate fails with InvalidStateException while DISABLED and works again once re-enabled."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    _register_ca_cleanup(ctx, ca_arn)
    _activate_root_ca(ctx, ca_arn)
    status = _wait_for_ca_status(ctx, ca_arn, {"ACTIVE"})
    assert status == "ACTIVE", f"expected freshly-activated CA status ACTIVE, got {status}"

    csr_pem = _make_csr_pem(f"{ctx.unique_name('sim2real-leaf-')[:60]}.example.com")

    # 1) Issuance succeeds while ACTIVE.
    first_cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem,
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Value": 30, "Type": "DAYS"},
    )["CertificateArn"]
    first_cert_pem = _poll_get_certificate(ctx, ca_arn, first_cert_arn)
    assert "BEGIN CERTIFICATE" in first_cert_pem, (
        f"expected a PEM certificate body from GetCertificate while CA is ACTIVE, got {first_cert_pem!r}"
    )

    # 2) Disable -> reflected on describe.
    acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
    status = _wait_for_ca_status(ctx, ca_arn, {"DISABLED"})
    assert status == "DISABLED", f"expected CA status DISABLED after UpdateCertificateAuthority, got {status}"

    # 3) Issuance is now blocked.
    code = _error_code(
        lambda: acmpca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr_pem,
            SigningAlgorithm="SHA256WITHRSA",
            Validity={"Value": 30, "Type": "DAYS"},
        )
    )
    assert code == ("InvalidStateException", "The certificate authority is not in a valid state for issuing certificates"), (
        f"expected IssueCertificate on a DISABLED CA to raise InvalidStateException with AWS's "
        f"exact message, got {code}"
    )

    # 4) Re-enable -> reflected on describe.
    acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="ACTIVE")
    status = _wait_for_ca_status(ctx, ca_arn, {"ACTIVE"})
    assert status == "ACTIVE", f"expected CA status ACTIVE after re-enabling, got {status}"

    # 5) Issuance works again. Use a freshly generated CSR (distinct key) so
    # the resulting certificate -- and its ARN, which encodes the issued
    # certificate's serial number -- is guaranteed distinct from the first.
    second_csr_pem = _make_csr_pem(f"{ctx.unique_name('sim2real-leaf-')[:60]}.example.com")
    second_cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=second_csr_pem,
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Value": 30, "Type": "DAYS"},
    )["CertificateArn"]
    second_cert_pem = _poll_get_certificate(ctx, ca_arn, second_cert_arn)
    assert "BEGIN CERTIFICATE" in second_cert_pem, (
        f"expected a PEM certificate body from GetCertificate after re-enabling the CA, got {second_cert_pem!r}"
    )
    assert second_cert_arn != first_cert_arn, (
        f"expected the post-re-enable issuance to mint a distinct certificate ARN, both were {second_cert_arn}"
    )


def _make_csr_pem(common_name: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(Encoding.PEM)


def _error_code(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


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
