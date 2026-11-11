"""import-ca-certificate-mismatched-key-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-ca-certificate-mismatched-key-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportCertificateAuthorityCertificate refuses a certificate whose key does not match the
    CA's CSR with CertificateMismatchException, leaving it PENDING_CERTIFICATE; a certificate
    issued for the CA's own CSR imports and activates it."""
    _require_cryptography()
    pca = ctx.client("acm-pca")

    common_name = ctx.unique_name("sim2real-pca-")[:64]
    arn = _create_ca(ctx, common_name)
    csr_pem = _wait_for_csr(ctx, arn)

    # negative: import a self-signed certificate with the CA's own subject but
    # built from an unrelated key pair
    wrong_cert_pem = _generate_self_signed_cert(common_name)
    refusal = _error(
        lambda: pca.import_certificate_authority_certificate(
            CertificateAuthorityArn=arn, Certificate=wrong_cert_pem
        )
    )
    assert refusal == (
        "CertificateMismatchException",
        "The certificate subject public key info field contains a different public key "
        "or key algorithm than the CA certificate signing request.",
    ), refusal

    status = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
    assert status == "PENDING_CERTIFICATE", f"CA advanced past PENDING_CERTIFICATE despite rejected import: {status!r}"

    # independent side-channel confirming no certificate was installed by the
    # rejected import: GetCertificateAuthorityCertificate refuses with the
    # specific "nothing to get" error rather than returning a certificate.
    get_refusal = _error(
        lambda: pca.get_certificate_authority_certificate(CertificateAuthorityArn=arn)
    )
    assert get_refusal == (
        "InvalidStateException",
        f"The certificate authority {arn} is not in the correct state to have a certificate signing request.",
    ), get_refusal

    # positive control: self-issue a root certificate matching the CA's actual CSR
    # public key and import that instead -- it activates the CA
    root_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr_pem,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    cert_pem = _wait_for_certificate(ctx, arn, root_cert_arn)
    pca.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=cert_pem)
    _wait_for_ca_status(ctx, arn, "ACTIVE")

    # independent read at the destination: the activated CA now serves back the
    # exact certificate that was imported, not just a bare ACTIVE status word.
    activated_cert = pca.get_certificate_authority_certificate(CertificateAuthorityArn=arn)["Certificate"]
    assert activated_cert.strip() == cert_pem.strip(), (
        "activated CA's certificate does not match the certificate that was imported"
    )


def _require_cryptography() -> None:
    import cryptography  # noqa: F401


def _generate_self_signed_cert(common_name: str) -> bytes:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _create_ca(ctx, common_name: str) -> str:
    pca = ctx.client("acm-pca")
    resp = pca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
        },
        CertificateAuthorityType="ROOT",
        IdempotencyToken=str(uuid.uuid4()).replace("-", "")[:32],
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _cleanup_ca(ctx, arn))
    _wait_for_ca_status(ctx, arn, "PENDING_CERTIFICATE")
    return arn


def _wait_for_csr(ctx, arn: str, timeout_s: float = 60.0) -> str:
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "RequestInProgressException":
                raise
        time.sleep(2)
    raise AssertionError("CSR was never ready within timeout")


def _wait_for_certificate(ctx, ca_arn: str, cert_arn: str, timeout_s: float = 60.0) -> str:
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "RequestInProgressException":
                raise
        time.sleep(2)
    raise AssertionError("certificate was never ready within timeout")


def _wait_for_ca_status(ctx, arn: str, target: str, timeout_s: float = 90.0) -> None:
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if last == target:
            return
        time.sleep(2)
    raise AssertionError(f"CA status never reached {target!r}, last seen {last!r}")


def _cleanup_ca(ctx, arn: str) -> None:
    pca = ctx.client("acm-pca")
    try:
        status = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
        try:
            pca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _wait_for_ca_status(ctx, arn, "DISABLED", timeout_s=60.0)
    if status != "DELETED":
        deadline = time.monotonic() + 30.0
        while True:
            try:
                pca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)
                return
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "InvalidStateException" or time.monotonic() > deadline:
                    raise
                time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
