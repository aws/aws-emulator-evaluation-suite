"""certificate-mismatch-import-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "certificate-mismatch-import-rejected"
GROUP = "server-side"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportCertificateAuthorityCertificate with a CertificateChain that did not sign the subordinate
    certificate is rejected with CertificateMismatchException and the CA stays PENDING_CERTIFICATE;
    the same CA activates once the correct chain is supplied."""
    try:
        from cryptography import x509  # noqa: F401
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"]) from exc

    acm_pca = ctx.client("acm-pca")

    ca_arn = _create_subordinate_ca(ctx, acm_pca)
    _wait_for_ca_status(acm_pca, ca_arn, {"PENDING_CERTIFICATE"})
    csr_pem = acm_pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]

    good_key, good_root = _generate_self_signed_root("sim2real matching root")
    bad_key, bad_root = _generate_self_signed_root("sim2real unrelated root")
    sub_cert = _sign_csr_as_subordinate(csr_pem, good_key, good_root)

    sub_cert_pem = sub_cert.public_bytes(_encoding())
    good_root_pem = good_root.public_bytes(_encoding())
    bad_root_pem = bad_root.public_bytes(_encoding())

    # --- break exactly one thing: pair the correctly-signed cert with the WRONG chain ---
    code, message = _error_code(
        lambda: acm_pca.import_certificate_authority_certificate(
            CertificateAuthorityArn=ca_arn,
            Certificate=sub_cert_pem,
            CertificateChain=bad_root_pem,
        )
    )
    assert code == "CertificateMismatchException", f"unexpected error code: {code}"
    assert message == "Certificate does not chain up to certificate chain provided.", (
        f"unexpected CertificateMismatchException message: {message!r}"
    )

    # --- effect absent: no certificate was installed on the CA ---
    status_after_reject = acm_pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
        "CertificateAuthority"
    ]["Status"]
    assert status_after_reject == "PENDING_CERTIFICATE", (
        f"CA should still be awaiting a certificate, was {status_after_reject}"
    )
    get_code, get_message = _error_code(
        lambda: acm_pca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)
    )
    assert get_code == "InvalidStateException", f"unexpected error code: {get_code}"
    assert get_message == (
        f"The certificate authority {ca_arn} is not in the correct state to have a "
        "certificate signing request."
    ), f"unexpected InvalidStateException message: {get_message!r}"

    # --- positive control in the SAME file: the correct chain activates the CA ---
    acm_pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn,
        Certificate=sub_cert_pem,
        CertificateChain=good_root_pem,
    )
    final_status = _wait_for_ca_status(acm_pca, ca_arn, {"ACTIVE"})
    assert final_status == "ACTIVE", f"CA should activate once the matching chain is supplied, was {final_status}"
    resp = acm_pca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)
    installed = resp["Certificate"].strip()
    expected = sub_cert_pem.decode("utf-8").strip()
    assert installed == expected, f"installed certificate does not match the imported one: {installed!r} != {expected!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _encoding():
    from cryptography.hazmat.primitives import serialization
    return serialization.Encoding.PEM


def _generate_self_signed_root(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
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
        .not_valid_before(now - datetime.timedelta(minutes=10))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _sign_csr_as_subordinate(csr_pem: str, issuer_key, issuer_cert):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    now = datetime.datetime.utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=10))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
        .sign(issuer_key, hashes.SHA256())
    )


def _create_subordinate_ca(ctx, acm_pca) -> str:
    resp = acm_pca.create_certificate_authority(
        CertificateAuthorityType="SUBORDINATE",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-mismatch-")},
        },
        IdempotencyToken=ctx.unique_name("idem-")[:36],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _disable_and_delete_ca(acm_pca, ca_arn))
    return ca_arn


# Inside the 900 s acm-pca cleanup budget; the CA is the check's only resource.
_CA_TEARDOWN_S = 840.0


def _disable_and_delete_ca(acm_pca, ca_arn: str) -> None:
    """Disable an ACTIVE CA and delete it with the 7-day restoration period until it reads back
    DELETED, where billing stops; retry the documented in-progress answers every 2 s to the
    deadline and raise on anything else."""
    deadline = time.monotonic() + _CA_TEARDOWN_S
    status = None
    while True:
        try:
            status = acm_pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
                "CertificateAuthority"
            ]["Status"]
            if status == "DELETED":
                return
            if status == "ACTIVE":
                acm_pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
            elif status != "CREATING":
                acm_pca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("InvalidStateException", "ConcurrentModificationException"):
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"CA {ca_arn} not DELETED within {_CA_TEARDOWN_S}s (last status {status!r})")
        time.sleep(2)


def _wait_for_ca_status(acm_pca, ca_arn: str, target_statuses: set[str], timeout_s: float = 180.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        last = acm_pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(3.0)
    raise AssertionError(f"CA never reached {target_statuses}; last status={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
