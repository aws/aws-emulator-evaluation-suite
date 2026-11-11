"""import-certificate-mismatch-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "import-certificate-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Importing a self-signed certificate whose key does not match the CA's CSR is rejected with
    CertificateMismatchException and the CA stays PENDING_CERTIFICATE; the same CA activates with
    the certificate matching its own CSR."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    acmpca = ctx.client("acm-pca")

    # --- broken: CA A, imported with a certificate signed by an unrelated key pair ---
    ca_a_name = ctx.unique_name("pca-mm-a-")[:64]
    ca_a = _create_root_ca(ctx, ca_a_name)

    mismatched_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # The CA's own subject, so the public key is the only thing that differs.
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sim2Real Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, ca_a_name),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    mismatched_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(mismatched_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(mismatched_key, hashes.SHA256())
    )
    mismatched_pem = mismatched_cert.public_bytes(serialization.Encoding.PEM)

    refusal = _error(
        lambda: acmpca.import_certificate_authority_certificate(
            CertificateAuthorityArn=ca_a, Certificate=mismatched_pem
        )
    )
    assert refusal == (
        "CertificateMismatchException",
        "The certificate subject public key info field contains a different public key or key "
        "algorithm than the CA certificate signing request.",
    ), refusal

    # effect absent: CA A never left PENDING_CERTIFICATE, no cert got installed
    status = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_a)[
        "CertificateAuthority"
    ]["Status"]
    assert status == "PENDING_CERTIFICATE", f"CA A status changed despite rejected import: {status!r}"
    cert_get = _error(
        lambda: acmpca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_a)
    )
    assert cert_get == (
        "InvalidStateException",
        f"The certificate authority {ca_a} is not in the correct state to have a certificate "
        "signing request.",
    ), (
        f"expected InvalidStateException (no cert installed), got {cert_get!r}"
    )

    # --- restore: the SAME CA, given a certificate that DOES match its own CSR key,
    # now activates -- proving the earlier rejection was about the key mismatch on
    # this exact CA, not a general refusal to import anything onto it ---
    _activate_root_ca(ctx, ca_a)
    status_restored = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_a)[
        "CertificateAuthority"
    ]["Status"]
    assert status_restored == "ACTIVE", f"CA A did not activate once given its correct certificate: {status_restored!r}"


from botocore.exceptions import ClientError


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _teardown_ca(acmpca, arn):
    """An ACTIVE CA cannot be deleted, so disable it first (the check activates it)."""
    status = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
    if status == "ACTIVE":
        acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
        _poll_until(
            lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
                "CertificateAuthority"
            ]["Status"],
            lambda s: s == "DISABLED",
            timeout_s=60.0,
            interval_s=2.0,
        )
    acmpca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)


def _call_with_retry(fn, retry_codes, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in retry_codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"timed out waiting for retry-able call; last error: {last_exc}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")


def _create_root_ca(ctx, common_name):
    acmpca = ctx.client("acm-pca")
    config = {
        "KeyAlgorithm": "RSA_2048",
        "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"Country": "US", "Organization": "Sim2Real Test", "CommonName": common_name[:64]},
    }
    arn = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration=config,
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real", "Value": "import-certificate-mismatch-rejected"}],
    )["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(acmpca, arn))
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda status: status == "PENDING_CERTIFICATE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return arn


def _get_csr(ctx, arn):
    acmpca = ctx.client("acm-pca")
    return _call_with_retry(
        lambda: acmpca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"],
        retry_codes={"RequestInProgressException"},
        timeout_s=60.0,
        interval_s=2.0,
    )


def _activate_root_ca(ctx, arn):
    """Self-signs the ROOT CA's own CSR and imports it -- the documented root
    activation flow (get CSR -> IssueCertificate w/ RootCACertificate/V1 template ->
    GetCertificate -> ImportCertificateAuthorityCertificate)."""
    acmpca = ctx.client("acm-pca")
    csr = _get_csr(ctx, arn)
    cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 365, "Type": "DAYS"},
    )["CertificateArn"]
    cert = _call_with_retry(
        lambda: acmpca.get_certificate(CertificateAuthorityArn=arn, CertificateArn=cert_arn)[
            "Certificate"
        ],
        retry_codes={"RequestInProgressException"},
        timeout_s=60.0,
        interval_s=2.0,
    )
    _call_with_retry(
        lambda: acmpca.import_certificate_authority_certificate(
            CertificateAuthorityArn=arn, Certificate=cert.encode("utf-8")
        ),
        retry_codes={"RequestInProgressException", "ConcurrentModificationException"},
        timeout_s=60.0,
        interval_s=2.0,
    )
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda status: status == "ACTIVE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return cert


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
