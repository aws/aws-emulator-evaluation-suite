"""server-side-ca-certificate-chain-auto-assembled."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "server-side-ca-certificate-chain-auto-assembled"
GROUP = "server-side"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For a subordinate CA activated with a certificate signed by an external root, the
    returned CertificateChain is exactly that root, verifies the CA certificate's signature,
    and excludes the CA's own certificate."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"]) from exc

    acm_pca = ctx.client("acm-pca")

    ca_arn = _create_subordinate_ca(ctx, acm_pca)
    _wait_for_ca_status(acm_pca, ca_arn, {"PENDING_CERTIFICATE"})
    csr_pem = acm_pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]

    root_key, root_cert = _generate_self_signed_root("sim2real external root")
    sub_cert = _sign_csr_as_subordinate(csr_pem, root_key, root_cert)

    sub_cert_pem = sub_cert.public_bytes(_encoding())
    root_cert_pem = root_cert.public_bytes(_encoding())

    acm_pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn,
        Certificate=sub_cert_pem,
        CertificateChain=root_cert_pem,
    )
    _wait_for_ca_status(acm_pca, ca_arn, {"ACTIVE"})

    resp = acm_pca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)
    returned_cert = x509.load_pem_x509_certificate(resp["Certificate"].encode("utf-8"))
    returned_chain = x509.load_pem_x509_certificate(resp["CertificateChain"].encode("utf-8"))

    # 1. The server persisted exactly the CA certificate and root we submitted.
    returned_cert_fp = returned_cert.fingerprint(hashes.SHA256())
    returned_chain_fp = returned_chain.fingerprint(hashes.SHA256())
    sub_cert_fp = sub_cert.fingerprint(hashes.SHA256())
    root_cert_fp = root_cert.fingerprint(hashes.SHA256())
    assert returned_cert_fp == sub_cert_fp, (
        f"Certificate field fingerprint {returned_cert_fp.hex()} does not match the "
        f"imported subordinate certificate fingerprint {sub_cert_fp.hex()}"
    )
    assert returned_chain_fp == root_cert_fp, (
        f"CertificateChain field fingerprint {returned_chain_fp.hex()} does not match the "
        f"imported external root fingerprint {root_cert_fp.hex()}"
    )

    # 2. Certificate and CertificateChain are kept distinct (chain excludes the CA cert).
    assert returned_cert_fp != returned_chain_fp, (
        "Certificate and CertificateChain fields are byte-identical "
        f"(fingerprint {returned_cert_fp.hex()}); the CA's own certificate must not "
        "reappear inside its chain"
    )

    # 3. The returned chain forms a real, verifiable issuing hierarchy: the CA
    #    certificate's signature verifies against the chain's public key.
    _verify_signed_by(returned_cert, returned_chain)


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


def _verify_signed_by(cert, issuer_cert) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding

    issuer_public_key = issuer_cert.public_key()
    try:
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except InvalidSignature as exc:
        raise AssertionError(
            f"returned CA certificate (subject={cert.subject.rfc4514_string()}) signature "
            f"does not verify against the returned chain's public key "
            f"(issuer={issuer_cert.subject.rfc4514_string()})"
        ) from exc


def _create_subordinate_ca(ctx, acm_pca) -> str:
    resp = acm_pca.create_certificate_authority(
        CertificateAuthorityType="SUBORDINATE",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-sub-")},
        },
        IdempotencyToken=ctx.unique_name("idem-")[:36],
    )
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _disable_and_delete_ca(acm_pca, ca_arn))
    return ca_arn


def _disable_and_delete_ca(acm_pca, ca_arn: str) -> None:
    try:
        acm_pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        acm_pca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
