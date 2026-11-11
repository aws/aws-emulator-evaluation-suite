"""issue-certificate-malformed-csr-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "issue-certificate-malformed-csr-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """IssueCertificate with a syntactically invalid CSR byte blob is rejected with
    MalformedCSRException and issues no certificate, while a syntactically valid CSR
    submitted to the same ACTIVE CA right afterwards is issued successfully."""
    _require_cryptography()
    pca = ctx.client("acm-pca")

    arn = _create_ca(ctx, ctx.unique_name("sim2real-pca-")[:64])
    _activate_root_ca(ctx, arn)

    # base64 of arbitrary random bytes -- decodes fine as PEM/base64 (so it clears
    # the generic input-shape check) but is not valid PKCS#10 DER, which is what
    # actually triggers MalformedCSRException rather than a generic ValidationException.
    import base64

    garbage_der = base64.b64encode(uuid.uuid4().bytes * 8).decode("ascii")
    lines = "\n".join(garbage_der[i : i + 64] for i in range(0, len(garbage_der), 64))
    bad_csr = f"-----BEGIN CERTIFICATE REQUEST-----\n{lines}\n-----END CERTIFICATE REQUEST-----\n".encode()
    refusal = _error(
        lambda: pca.issue_certificate(
            CertificateAuthorityArn=arn,
            Csr=bad_csr,
            SigningAlgorithm="SHA256WITHRSA",
            Validity={"Value": 30, "Type": "DAYS"},
        )
    )
    assert refusal == ("MalformedCSRException", "Malformed CSR."), refusal

    # positive control: a syntactically valid CSR against the same ACTIVE CA succeeds
    good_csr = _generate_rsa_csr("sim2real-leaf")
    cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=good_csr,
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Value": 30, "Type": "DAYS"},
    )["CertificateArn"]
    cert_pem = _wait_for_certificate(ctx, arn, cert_arn)
    assert "BEGIN CERTIFICATE" in cert_pem, f"expected a PEM certificate body, got {cert_pem!r}"


def _require_cryptography() -> None:
    import cryptography  # noqa: F401


def _generate_rsa_csr(common_name: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


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
        # a CA's only handle is a server-minted UUID, never the common_name prefix; the tag is
        # what makes a stranded CA discoverable by tag.
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _activate_root_ca(ctx, arn: str) -> None:
    pca = ctx.client("acm-pca")
    csr_pem = _wait_for_csr(ctx, arn)
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
