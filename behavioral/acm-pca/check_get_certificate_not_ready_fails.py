"""get-certificate-not-ready-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-certificate-not-ready-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
# DeleteCertificateAuthority accepts PermanentDeletionTimeInDays in 7..30; 7 is the shortest
# soft-delete window the service allows.
_MIN_DELETION_DAYS = 7
# Short-lived-certificate-mode billing (~$50/CA/month, prorated) is far cheaper than the
# $400 general-purpose rate and is all this check needs to issue its own root cert.
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


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


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying teardown that ends at an OBSERVED Status == "DELETED".

    DeleteCertificateAuthority accepts only CREATING, PENDING_CERTIFICATE, DISABLED or FAILED,
    so a CA this check activated to ACTIVE must be DISABLED first. The meter stops on the
    DELETED status, not on the delete call, so this polls for it and raises (loudly, with the
    manual-recovery steps) rather than leaving a billed CA to leak silently.
    """
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 420
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe(ctx, ca_arn).get("Status")
        except ClientError:
            return  # not addressable any more; nothing left to bill
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
            except ClientError:
                pass
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=_MIN_DELETION_DAYS
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
        f"LEAKED BILLABLE RESOURCE: certificate authority {ca_arn} never reached "
        f"Status=DELETED within 420s (last observed {last_status!r}). It is STILL BILLING. "
        f"Delete it manually: UpdateCertificateAuthority(Status='DISABLED') then "
        f"DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_ca(ctx, **overrides):
    """Create a cheap ROOT CA (SHORT_LIVED_CERTIFICATE usage mode), tagged so a tag search
    can find it even though its only handle is a server-minted UUID, and register its
    teardown. Retries on throttling since CreateCertificateAuthority has a low request-rate
    limit."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": _USAGE_MODE,
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    body.update(overrides)
    resp = None
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
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


def _fetch_csr(ctx, ca_arn, *, timeout_s):
    """GetCertificateAuthorityCsr, polling through the creation-in-progress guard."""
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn).get("Csr")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("RequestInProgressException", "InvalidStateException"):
                return None
            raise

    return _poll_until(
        _probe, lambda v: bool(v), timeout_s=timeout_s, interval_s=2.0,
        description="GetCertificateAuthorityCsr returning a CSR",
    )


def _activate_root_ca(ctx, ca_arn, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR
    (privateca userguide, "Install a root CA certificate"): GetCertificateAuthorityCsr ->
    IssueCertificate with the RootCACertificate/V1 template against the CA's own arn ->
    ImportCertificateAuthorityCertificate. Returns the root certificate's ARN.
    """
    pca = ctx.client("acm-pca")
    _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching PENDING_CERTIFICATE",
    )
    csr_pem = _fetch_csr(ctx, ca_arn, timeout_s=timeout_s)
    root_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE,
        Validity={"Value": 3, "Type": "YEARS"},
    )["CertificateArn"]

    def _probe_signed():
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=root_cert_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "RequestInProgressException":
                return None
            raise

    signed = _poll_until(
        _probe_signed, lambda v: bool(v and v.get("Certificate")),
        timeout_s=timeout_s, interval_s=2.0,
        description=f"GetCertificate returning the signed root certificate for {root_cert_arn}",
    )
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=signed["Certificate"].encode("ascii")
    )
    _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching ACTIVE after importing its own signed certificate",
    )
    return root_cert_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCertificate on a CA that has issued nothing -> InvalidStateException; the identical
    operation, on the CA's own real certificate, succeeds once the CA is ACTIVE."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)

    refusal = _err(
        lambda: pca.get_certificate(
            CertificateAuthorityArn=arn,
            CertificateArn=arn + "/certificate/0123456789abcdef0123456789abcdef",
        )
    )
    assert refusal == (
        "InvalidStateException",
        f"The certificate authority {arn} is not in the correct state to have issued certificates.",
    ), refusal

    root_cert_arn = _activate_root_ca(ctx, arn, timeout_s=180)

    # The restore beat: the identical operation (GetCertificate on this CA), issued fresh and
    # independent of the polling that drove activation, now succeeds -- proving the earlier
    # refusal was tied to the CA's readiness state and not a blanket failure of this account,
    # credentials or client wiring.
    final = pca.get_certificate(CertificateAuthorityArn=arn, CertificateArn=root_cert_arn)
    cert_pem = final.get("Certificate", "")
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"expected GetCertificate on the now-ACTIVE CA to return a PEM certificate, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
