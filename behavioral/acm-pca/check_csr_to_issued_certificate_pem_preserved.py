"""csr-to-issued-certificate-pem-preserved."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "csr-to-issued-certificate-pem-preserved"
GROUP = "representation"
SERVICES = ["acm-pca"]

_KEY_ALGORITHM = "RSA_2048"
_SIGNING_ALGORITHM = "SHA256WITHRSA"
_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A root certificate issued from the CA's own GetCertificateAuthorityCsr keeps the CSR's
    exact subject and public key, so the issued certificate encodes the CSR rather than
    a regenerated key or identity."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    client = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, arn))
    _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE"}, timeout_s=90)

    csr_pem = client.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
    assert csr_pem.strip().startswith("-----BEGIN CERTIFICATE REQUEST-----"), (
        f"GetCertificateAuthorityCsr must return PEM-armored CSR, got {csr_pem[:64]!r}"
    )
    assert csr_pem.strip().endswith("-----END CERTIFICATE REQUEST-----"), (
        f"GetCertificateAuthorityCsr must return PEM-armored CSR, got {csr_pem[-64:]!r}"
    )

    cert_arn = client.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr_pem,
        SigningAlgorithm=_SIGNING_ALGORITHM,
        TemplateArn=_ROOT_TEMPLATE_ARN,
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    cert_pem = _wait_for_certificate(ctx, arn, cert_arn)
    assert cert_pem.strip().startswith("-----BEGIN CERTIFICATE-----"), (
        f"GetCertificate must return PEM-armored certificate, got {cert_pem[:64]!r}"
    )
    assert cert_pem.strip().endswith("-----END CERTIFICATE-----"), (
        f"GetCertificate must return PEM-armored certificate, got {cert_pem[-64:]!r}"
    )

    csr_obj = x509.load_pem_x509_csr(csr_pem.encode("ascii"), default_backend())
    cert_obj = x509.load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())

    # Subject preserved exactly -- no re-encoding drift of the RDN sequence.
    assert cert_obj.subject == csr_obj.subject, f"{cert_obj.subject} != {csr_obj.subject}"

    # Public key preserved exactly -- proves the certificate really was built from
    # *this* CSR's key material, not silently re-generated server-side.
    csr_numbers = csr_obj.public_key().public_numbers()
    cert_numbers = cert_obj.public_key().public_numbers()
    assert csr_numbers.n == cert_numbers.n and csr_numbers.e == cert_numbers.e, (
        f"issued certificate's RSA public key (n={cert_numbers.n}, e={cert_numbers.e}) does "
        f"not match the CSR's (n={csr_numbers.n}, e={csr_numbers.e})"
    )

    # The RootCACertificate/V1 template adds a CA:TRUE BasicConstraints extension
    # that is not present on the plain CSR -- confirming extensions requested by the
    # template are actually encoded into the issued certificate, not dropped.
    basic_constraints = cert_obj.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic_constraints.value.ca is True, (
        f"RootCACertificate/V1 template must encode CA:TRUE BasicConstraints, got "
        f"{basic_constraints.value.ca!r}"
    )


def _describe_status(ctx, arn: str) -> str:
    client = ctx.client("acm-pca")
    return client.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]


def _wait_for_status(ctx, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_status(ctx, arn)
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"status never reached {target_statuses}, last seen {last}")


def _create_ca(ctx, ca_type: str = "ROOT") -> str:
    client = ctx.client("acm-pca")
    cn = ctx.unique_name("sim2real-pca-")[:64]
    resp = client.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": _KEY_ALGORITHM,
            "SigningAlgorithm": _SIGNING_ALGORITHM,
            "Subject": {"CommonName": cn},
        },
        CertificateAuthorityType=ca_type,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    return resp["CertificateAuthorityArn"]


def _wait_for_certificate(ctx, ca_arn: str, cert_arn: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    client = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last_code: str | None = None
    while time.monotonic() < deadline:
        try:
            return client.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"certificate never became available, last error: {last_code}")


def _best_effort_delete(ctx, arn: str) -> None:
    client = ctx.client("acm-pca")
    try:
        status = _describe_status(ctx, arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETED":
        return
    if status == "ACTIVE":
        client.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
        _wait_for_status(ctx, arn, {"DISABLED"}, timeout_s=60)
    client.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
