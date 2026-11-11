"""import-ca-certificate-base64-byte-preservation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "import-ca-certificate-base64-byte-preservation"
GROUP = "representation"
SERVICES = ["acm-pca"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """The exact PEM bytes handed to ImportCertificateAuthorityCertificate come back
    byte-identical from GetCertificateAuthorityCertificate -- no re-encoding, no
    re-wrapping of the base64 body, no added/stripped whitespace."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx, ctx.unique_name("pca-imp-"))

    # _activate_root_ca performs ImportCertificateAuthorityCertificate itself and
    # returns the exact PEM string it fed to that call.
    imported_cert_pem = _activate_root_ca(ctx, ca_arn)
    imported_bytes = imported_cert_pem.encode("utf-8")

    fetched = acmpca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)
    fetched_cert_pem = fetched["Certificate"]

    assert fetched_cert_pem == imported_cert_pem, (
        "GetCertificateAuthorityCertificate did not return the imported certificate "
        f"verbatim:\nIMPORTED={imported_cert_pem!r}\nFETCHED={fetched_cert_pem!r}"
    )
    assert fetched_cert_pem.encode("utf-8") == imported_bytes


from botocore.exceptions import ClientError


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
    )["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, arn))
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda status: status == "PENDING_CERTIFICATE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return arn


def _safe_delete_ca(ctx, arn):
    """Disable an ACTIVE CA before deleting it; AWS rejects deleting an ACTIVE CA."""
    acmpca = ctx.client("acm-pca")

    def _status():
        return acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
            "CertificateAuthority"
        ]["Status"]

    try:
        status = _status()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETED":
        return
    if status == "ACTIVE":
        acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
        _poll_until(_status, lambda s: s == "DISABLED", timeout_s=60.0, interval_s=2.0)
    _call_with_retry(
        lambda: acmpca.delete_certificate_authority(
            CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7
        ),
        retry_codes={"InvalidStateException"},
        timeout_s=60.0,
        interval_s=3.0,
    )


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
    GetCertificate -> ImportCertificateAuthorityCertificate). Returns the exact PEM
    string that was passed to ImportCertificateAuthorityCertificate."""
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
