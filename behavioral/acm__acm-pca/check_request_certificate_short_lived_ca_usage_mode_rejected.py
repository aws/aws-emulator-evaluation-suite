"""request-certificate-short-lived-ca-usage-mode-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-certificate-short-lived-ca-usage-mode-rejected"
GROUP = 'data-plane'
SERVICES = ['acm', 'acm-pca']

_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_MIN_DELETION_DAYS = 7
_TERMINAL_STATUSES = ("ISSUED", "FAILED")


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


def _create_ca(ctx, usage_mode):
    """Create a ROOT private CA in the given usage mode and register its teardown."""
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
                UsageMode=usage_mode,
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


def _request_and_await_terminal(ctx, ca_arn, domain, *, timeout_s):
    acm = ctx.client("acm")
    cert_arn = acm.request_certificate(
        DomainName=domain, CertificateAuthorityArn=ca_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    cert = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda c: c.get("Status") in _TERMINAL_STATUSES,
        timeout_s=timeout_s, interval_s=2.0, description=f"certificate for {domain} reaching a terminal status",
    )
    return cert_arn, cert


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """RequestCertificate against a SHORT_LIVED_CERTIFICATE-mode private CA settles in Status
    FAILED with FailureReason PCA_NOT_SUPPORTED_VIA_ACM and never reaches ISSUED, while the
    identical request against a GENERAL_PURPOSE-mode CA reaches ISSUED."""
    timeout_s = 240

    short_ca_arn = _create_ca(ctx, "SHORT_LIVED_CERTIFICATE")
    _activate_root_ca(ctx, short_ca_arn, timeout_s=timeout_s)
    general_ca_arn = _create_ca(ctx, "GENERAL_PURPOSE")
    _activate_root_ca(ctx, general_ca_arn, timeout_s=timeout_s)

    short_domain = f"{ctx.unique_name('sim2real-acmshort-').lower()}.example.com"
    _short_cert_arn, short_cert = _request_and_await_terminal(
        ctx, short_ca_arn, short_domain, timeout_s=timeout_s
    )
    assert short_cert["Status"] == "FAILED", (
        f"expected a certificate requested against a SHORT_LIVED_CERTIFICATE CA to settle "
        f"FAILED, got {short_cert['Status']!r}"
    )
    assert short_cert["FailureReason"] == "PCA_NOT_SUPPORTED_VIA_ACM", (
        f"expected FailureReason PCA_NOT_SUPPORTED_VIA_ACM, got {short_cert.get('FailureReason')!r}"
    )

    general_domain = f"{ctx.unique_name('sim2real-acmgen-').lower()}.example.com"
    _general_cert_arn, general_cert = _request_and_await_terminal(
        ctx, general_ca_arn, general_domain, timeout_s=timeout_s
    )
    assert general_cert["Status"] == "ISSUED", (
        f"positive control failed: a certificate requested against a GENERAL_PURPOSE CA "
        f"settled {general_cert['Status']!r} instead of ISSUED"
    )
    assert general_cert["Type"] == "PRIVATE", general_cert["Type"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
