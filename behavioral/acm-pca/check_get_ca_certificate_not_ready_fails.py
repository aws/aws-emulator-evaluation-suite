"""get-ca-certificate-not-ready-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-ca-certificate-not-ready-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
# SHORT_LIVED_CERTIFICATE-mode CAs are the cheapest usage mode ($50/CA/month prorated,
# vs. $400 for GENERAL_PURPOSE) and this check never needs to issue anything long-lived.
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"


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


def _err(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying, LOUD teardown that ends at an OBSERVED Status == "DELETED".

    DeleteCertificateAuthority accepts only CREATING, PENDING_CERTIFICATE, DISABLED or FAILED, so
    an ACTIVE CA (this check activates its own CA to get the restore leg) must be DISABLED first.
    A cleanup that fires one delete and swallows the exception leaks a metered private CA, so
    this polls to the DELETED status and raises if it never arrives.
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
                pca.update_certificate_authority(
                    CertificateAuthorityArn=ca_arn, Status="DISABLED"
                )
            except ClientError:
                pass
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
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


def _create_ca(ctx, scenario, **overrides):
    """Create a ROOT CA, tagged (its only handle is a server-minted UUID, so untagged it is
    invisible to a tag search), and register its teardown before anything can assert."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": _USAGE_MODE,
        "Tags": [{"Key": "sim2real", "Value": scenario}],
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


def _await_certificate(ctx, ca_arn, cert_arn, *, timeout_s):
    """GetCertificate, polling through RequestInProgressException until signing completes."""
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "RequestInProgressException":
                return None
            raise

    got = _poll_until(
        _probe, lambda v: bool(v and v.get("Certificate")),
        timeout_s=timeout_s, interval_s=2.0,
        description=f"GetCertificate returning a signed certificate for {cert_arn}",
    )
    return got["Certificate"]


def _activate_root_ca(ctx, ca_arn, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR: the
    documented root-CA installation sequence (GetCertificateAuthorityCsr -> IssueCertificate
    against the CA's own arn -> GetCertificate -> ImportCertificateAuthorityCertificate).
    Returns the CA certificate PEM that was imported."""
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
    ca_cert_pem = _await_certificate(ctx, ca_arn, root_cert_arn, timeout_s=timeout_s)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=ca_cert_pem.encode("ascii")
    )
    _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching ACTIVE after importing its own signed certificate",
    )
    return ca_cert_pem


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCertificateAuthorityCertificate on a CA with no certificate installed is refused with
    InvalidStateException; the same call on the same CA, once activated, returns exactly the
    imported certificate, so the refusal is state-specific and not a blanket one."""
    pca = ctx.client("acm-pca")
    timeout_s = 240
    scenario = "acm-pca-get-ca-certificate-not-ready"

    arn = _create_ca(ctx, scenario)

    # --- break (natural): a freshly created CA has no installed certificate yet ---
    refusal = _err(
        lambda: pca.get_certificate_authority_certificate(CertificateAuthorityArn=arn)
    )
    assert refusal == (
        "InvalidStateException",
        f"The certificate authority {arn} is not in the correct state to have a certificate "
        f"signing request.",
    ), (
        f"expected InvalidStateException with AWS's exact message from "
        f"GetCertificateAuthorityCertificate on a CA with no installed certificate, got {refusal!r}"
    )

    # --- effect absent via an independent read: Describe confirms no certificate landed.
    # CREATING is transient, so the read waits for the CA to settle and grades the resting
    # PENDING_CERTIFICATE status; ACTIVE (a certificate landed) would falsify the check.
    status = _poll_until(
        lambda: _describe(ctx, arn).get("Status"),
        lambda st: st != "CREATING",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA leaving CREATING",
    )
    assert status == "PENDING_CERTIFICATE", (
        f"expected the CA to not yet be ACTIVE after the refused "
        f"GetCertificateAuthorityCertificate call, got Status={status!r}"
    )

    # --- restore: activate the CA, which also serves as the positive control ---
    imported_pem = _activate_root_ca(ctx, arn, timeout_s=timeout_s)

    # --- identical call now succeeds, returning exactly what was imported ---
    resp = pca.get_certificate_authority_certificate(CertificateAuthorityArn=arn)
    got_cert = resp.get("Certificate")
    assert got_cert == imported_pem, (
        "GetCertificateAuthorityCertificate succeeded after activation but did not return the "
        f"certificate that was imported: got {got_cert!r}, expected {imported_pem!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
