"""request-certificate-private-ca-type-and-export."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-certificate-private-ca-type-and-export"
GROUP = 'data-plane'
SERVICES = ['acm', 'acm-pca']

_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_MIN_DELETION_DAYS = 7


def _poll_until(probe, predicate, *, timeout_s=180, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_ca(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Disable an ACTIVE CA then delete it, polling to an observed DELETED status.

    DeleteCertificateAuthority only accepts CREATING, PENDING_CERTIFICATE, DISABLED or FAILED,
    and the per-CA meter only stops once the CA is observed DELETED.
    """
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 420
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe_ca(ctx, ca_arn).get("Status")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ConcurrentModificationException":
                    raise
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=_MIN_DELETION_DAYS,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(3)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(
        f"certificate authority {ca_arn} never reached Status=DELETED within 420s "
        f"(last observed {last_status!r})"
    )


def _create_ca(ctx):
    """Create a ROOT private CA in GENERAL_PURPOSE usage mode and register its teardown.

    ACM's RequestCertificate cannot issue through a SHORT_LIVED_CERTIFICATE-mode CA
    (FailureReason PCA_NOT_SUPPORTED_VIA_ACM), so this check uses the mode ACM supports.
    """
    pca = ctx.client("acm-pca")
    resp = None
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(
                CertificateAuthorityConfiguration={
                    "KeyAlgorithm": "RSA_2048",
                    "SigningAlgorithm": "SHA256WITHRSA",
                    "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
                },
                CertificateAuthorityType="ROOT",
                UsageMode="GENERAL_PURPOSE",
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    assert resp is not None, "CreateCertificateAuthority did not return after 6 attempts"
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(ctx, ca_arn))
    return ca_arn


def _activate_root_ca(ctx, ca_arn, *, timeout_s):
    """Install a self-signed root certificate so the CA reaches ACTIVE and can issue certificates."""
    pca = ctx.client("acm-pca")
    _poll_until(
        lambda: _describe_ca(ctx, ca_arn), lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0, description="CA reaching PENDING_CERTIFICATE",
    )

    def _fetch_csr():
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn).get("Csr")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "RequestInProgressException", "InvalidStateException",
            ):
                return None
            raise

    csr_pem = _poll_until(
        _fetch_csr, lambda v: bool(v), timeout_s=timeout_s, interval_s=2.0,
        description="GetCertificateAuthorityCsr returning a CSR",
    )
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
            if exc.response.get("Error", {}).get("Code") == "RequestInProgressException":
                return None
            raise

    got = _poll_until(
        _fetch_root_cert, lambda v: bool(v and v.get("Certificate")), timeout_s=timeout_s,
        interval_s=2.0, description="GetCertificate returning the signed root certificate",
    )
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=got["Certificate"].encode("ascii")
    )
    _poll_until(
        lambda: _describe_ca(ctx, ca_arn), lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0, description="CA reaching ACTIVE after self-activation",
    )


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A certificate RequestCertificate issues against a private CA reports Type PRIVATE in
    DescribeCertificate and ListCertificates, and ExportCertificate returns a certificate, chain
    and private key whose public key matches the issued certificate."""
    acm = ctx.client("acm")
    timeout_s = 240

    ca_arn = _create_ca(ctx)
    _activate_root_ca(ctx, ca_arn, timeout_s=timeout_s)

    domain = f"{ctx.unique_name('sim2real-acmpriv-').lower()}.example.com"
    cert_arn = acm.request_certificate(
        DomainName=domain,
        CertificateAuthorityArn=ca_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    cert = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda c: c.get("Status") == "ISSUED",
        timeout_s=timeout_s, interval_s=2.0, description="certificate reaching ISSUED",
    )
    assert cert["Type"] == "PRIVATE", (
        f"expected Type PRIVATE for a certificate requested with CertificateAuthorityArn, "
        f"got {cert['Type']!r}"
    )
    assert cert["CertificateAuthorityArn"] == ca_arn, cert.get("CertificateAuthorityArn")
    assert cert["DomainName"] == domain, cert["DomainName"]

    pages = acm.get_paginator("list_certificates").paginate()
    summary = next(
        (s for page in pages for s in page["CertificateSummaryList"] if s["CertificateArn"] == cert_arn),
        None,
    )
    assert summary is not None, f"ListCertificates did not return {cert_arn!r}"
    assert summary["Type"] == "PRIVATE", (
        f"ListCertificates reported Type {summary['Type']!r} for a private-CA-issued "
        f"certificate, expected PRIVATE"
    )

    passphrase = b"sim2real-pass-1234"
    exported = acm.export_certificate(CertificateArn=cert_arn, Passphrase=passphrase)
    assert "Certificate" in exported, "ExportCertificate response carried no Certificate"
    assert "CertificateChain" in exported, "ExportCertificate response carried no CertificateChain"
    assert "PrivateKey" in exported, "ExportCertificate response carried no PrivateKey"

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    exported_cert_bytes = exported["Certificate"]
    if isinstance(exported_cert_bytes, str):
        exported_cert_bytes = exported_cert_bytes.encode("ascii")
    exported_cert = x509.load_pem_x509_certificate(exported_cert_bytes)

    key_pem = exported["PrivateKey"]
    if isinstance(key_pem, str):
        key_pem = key_pem.encode("ascii")
    private_key = serialization.load_pem_private_key(key_pem, password=passphrase)

    exported_spki = exported_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_spki = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert exported_spki == key_spki, (
        "the exported private key's public key does not match the exported certificate's -- "
        "ExportCertificate returned a key that does not belong to this certificate"
    )

    chain_bytes = exported["CertificateChain"]
    if isinstance(chain_bytes, str):
        chain_bytes = chain_bytes.encode("ascii")
    chain_cert = x509.load_pem_x509_certificate(chain_bytes)
    assert chain_cert.subject == exported_cert.issuer, (
        "the exported certificate chain's leading certificate is not the issuer of the "
        "exported certificate"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
