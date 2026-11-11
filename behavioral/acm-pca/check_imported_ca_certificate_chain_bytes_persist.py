"""imported-ca-certificate-chain-bytes-persist."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "imported-ca-certificate-chain-bytes-persist"
GROUP = "representation"
SERVICES = ["acm-pca"]

_KEY_ALGORITHM = "RSA_2048"
_SIGNING_ALGORITHM = "SHA256WITHRSA"
_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_SUBORDINATE_TEMPLATE_ARN = "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A subordinate CA certificate and chain imported with ImportCertificateAuthorityCertificate
    come back byte-for-byte from GetCertificateAuthorityCertificate, with no PEM transcoding
    drift across the round trip."""
    client = ctx.client("acm-pca")

    root_arn = _create_ca(ctx, ca_type="ROOT")
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, root_arn))
    _activate_root_ca(ctx, root_arn)
    root_status = _describe_status(ctx, root_arn)
    assert root_status == "ACTIVE", f"expected root CA to be ACTIVE after activation, got {root_status!r}"

    sub_arn = _create_ca(ctx, ca_type="SUBORDINATE")
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, sub_arn))
    _wait_for_status(ctx, sub_arn, {"PENDING_CERTIFICATE"}, timeout_s=90)

    sub_csr = client.get_certificate_authority_csr(CertificateAuthorityArn=sub_arn)["Csr"]
    sub_cert_arn = client.issue_certificate(
        CertificateAuthorityArn=root_arn,
        Csr=sub_csr,
        SigningAlgorithm=_SIGNING_ALGORITHM,
        TemplateArn=_SUBORDINATE_TEMPLATE_ARN,
        Validity={"Value": 5, "Type": "YEARS"},
    )["CertificateArn"]
    issued = _wait_for_certificate_full(ctx, root_arn, sub_cert_arn)
    sub_cert_pem = issued["Certificate"]
    chain_pem = issued["CertificateChain"]
    assert chain_pem, "expected a non-empty certificate chain for a certificate issued by a root CA"
    assert chain_pem.strip().startswith("-----BEGIN CERTIFICATE-----"), (
        f"expected the certificate chain to start with a PEM certificate header, got {chain_pem[:40]!r}"
    )

    client.import_certificate_authority_certificate(
        CertificateAuthorityArn=sub_arn,
        Certificate=sub_cert_pem,
        CertificateChain=chain_pem,
    )
    _wait_for_status(ctx, sub_arn, {"ACTIVE"}, timeout_s=90)

    stored = client.get_certificate_authority_certificate(CertificateAuthorityArn=sub_arn)
    assert stored["Certificate"] == sub_cert_pem, "leaf CA certificate bytes drifted between import and retrieval"
    assert stored["CertificateChain"] == chain_pem, "certificate chain bytes drifted between import and retrieval"


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


def _wait_for_certificate_full(ctx, ca_arn: str, cert_arn: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> dict[str, str]:
    client = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last_code: str | None = None
    while time.monotonic() < deadline:
        try:
            return client.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"certificate never became available, last error: {last_code}")


def _activate_root_ca(ctx, arn: str) -> str:
    """Self-issue and import a root CA certificate, driving PENDING_CERTIFICATE -> ACTIVE.
    Returns the certificate PEM that was imported."""
    client = ctx.client("acm-pca")
    _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE"}, timeout_s=90)
    csr = client.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
    cert_arn = client.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr,
        SigningAlgorithm=_SIGNING_ALGORITHM,
        TemplateArn=_ROOT_TEMPLATE_ARN,
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    certificate = _wait_for_certificate_full(ctx, arn, cert_arn)["Certificate"]
    client.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=certificate)
    _wait_for_status(ctx, arn, {"ACTIVE"}, timeout_s=90)
    return certificate


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
