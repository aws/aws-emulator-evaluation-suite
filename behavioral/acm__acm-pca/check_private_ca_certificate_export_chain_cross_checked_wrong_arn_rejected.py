"""private-ca-certificate-export-chain-cross-checked-wrong-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "private-ca-certificate-export-chain-cross-checked-wrong-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["acm", "acm-pca"]

_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"


def _poll(probe, predicate, *, timeout_s=240.0, interval_s=2.0, description="condition"):
    """Poll ``probe()`` until ``predicate`` is truthy; return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not reached within {timeout_s}s; last observed {last!r}")


def _expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _describe_ca(pca, ca_arn):
    return pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]


def _teardown_ca(pca, ca_arn):
    """Disable then delete the CA, polling to a DELETED or already-gone terminal status."""

    def run_undo() -> None:
        deadline = time.monotonic() + 300.0
        while time.monotonic() < deadline:
            try:
                status = _describe_ca(pca, ca_arn).get("Status")
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            if status == "DELETED":
                return
            if status == "ACTIVE":
                try:
                    pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ConcurrentModificationException":
                        raise
                time.sleep(2)
                continue
            if status in ("DISABLED", "FAILED", "CREATING"):
                try:
                    pca.delete_certificate_authority(
                        CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
                    )
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code in ("InvalidStateException", "ConcurrentModificationException"):
                        time.sleep(2)
                        continue
                    if code == "ResourceNotFoundException":
                        return
                    raise
            time.sleep(2)
        raise AssertionError(f"certificate authority {ca_arn} never reached DELETED within 300s")

    return run_undo


def _create_active_root_ca(ctx):
    """Create a ROOT private CA and self-activate it so RequestCertificate can issue through it."""
    pca = ctx.client("acm-pca")
    resp = pca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-xsvc-acmpca-").rstrip("-")},
        },
        CertificateAuthorityType="ROOT",
        UsageMode="GENERAL_PURPOSE",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(_teardown_ca(pca, ca_arn))

    _poll(
        lambda: _describe_ca(pca, ca_arn), lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        description="CA reaching PENDING_CERTIFICATE",
    )
    csr_pem = pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    root_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE,
        Validity={"Value": 3, "Type": "YEARS"},
    )["CertificateArn"]

    def _fetch_root_cert():
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=root_cert_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    signed = _poll(
        _fetch_root_cert, lambda v: bool(v and v.get("Certificate")),
        description="GetCertificate returning the self-signed root",
    )
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=signed["Certificate"].encode("ascii")
    )
    _poll(
        lambda: _describe_ca(pca, ca_arn), lambda c: c.get("Status") == "ACTIVE",
        description="CA reaching ACTIVE after self-activation",
    )
    return ca_arn


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExportCertificate on a certificate issued by a root private CA returns a chain led by
    that CA's certificate, which verifies the leaf's signature, and a passphrase-encrypted key
    matching the leaf; an unknown certificate ARN is refused with ResourceNotFoundException.
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    acm = ctx.client("acm")
    pca = ctx.client("acm-pca")

    ca_arn = _create_active_root_ca(ctx)

    domain = f"{ctx.unique_name('sim2real-xsvc-acmpca-').lower()}.example.com"
    cert_arn = acm.request_certificate(
        DomainName=domain,
        CertificateAuthorityArn=ca_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    _poll(
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda c: c.get("Status") == "ISSUED", description="certificate reaching ISSUED",
    )

    passphrase = b"sim2real-xsvc-pass-9183"
    exported = acm.export_certificate(CertificateArn=cert_arn, Passphrase=passphrase)

    leaf = x509.load_pem_x509_certificate(exported["Certificate"].encode("ascii"))
    chain_cert = x509.load_pem_x509_certificate(exported["CertificateChain"].encode("ascii"))
    private_key = serialization.load_pem_private_key(
        exported["PrivateKey"].encode("ascii"), password=passphrase
    )

    leaf_spki = leaf.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_spki = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert leaf_spki == key_spki, (
        "the exported private key's public key does not match the exported certificate's public key"
    )

    ca_cert_der = x509.load_pem_x509_certificate(
        pca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)["Certificate"].encode("ascii")
    ).public_bytes(encoding=serialization.Encoding.DER)
    chain_der = chain_cert.public_bytes(encoding=serialization.Encoding.DER)
    assert chain_der == ca_cert_der, (
        "the exported certificate chain's leading certificate is not byte-identical to the "
        "account's own CA certificate from GetCertificateAuthorityCertificate"
    )

    try:
        chain_cert.public_key().verify(
            leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm,
        )
    except InvalidSignature as exc:
        raise AssertionError(
            "the exported certificate's signature does not verify under the exported chain's "
            "public key"
        ) from exc

    fake_arn = f"arn:aws:acm:{ctx.region}:{ctx.account}:certificate/00000000-0000-0000-0000-000000000000"
    not_found = ("ResourceNotFoundException", f"Could not find certificate {fake_arn}.")
    _expect_error(lambda: acm.export_certificate(CertificateArn=fake_arn, Passphrase=passphrase), *not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
