"""get-csr-not-ready-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-csr-not-ready-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

def _err_resp(fn):
    """Call fn(); return the full botocore error response if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response
    return None

def _delete_ca(ctx, ca_arn):
    try:
        ctx.client("acm-pca").delete_certificate_authority(
            CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _describe_status(pca, ca_arn):
    return pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; raise loudly on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last observed: {last!r})")

def _create_ca(ctx, **overrides):
    """Create a cheap, never-activated ROOT CA (SHORT_LIVED_CERTIFICATE usage mode,
    never issues a cert) and register its teardown. Retries on throttling since
    CreateCertificateAuthority has a low request-rate limit."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    body.update(overrides)
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
            break
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "response", {}).get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, ca_arn))
    return ca_arn

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCertificateAuthorityCsr on a CA still CREATING is refused with RequestInProgressException,
    and the identical call succeeds with a real CSR once the same CA reaches PENDING_CERTIFICATE."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    err = _err_resp(
        lambda: pca.get_certificate_authority_csr(CertificateAuthorityArn=arn)
    )
    assert err is not None, "GetCertificateAuthorityCsr unexpectedly succeeded on a just-created CA"
    refusal = (err.get("Error", {}).get("Code"), err.get("Error", {}).get("Message"))
    assert refusal == (
        "RequestInProgressException",
        "The request to create certificate authority is still in progress. Try again later.",
    ), (
        f"expected RequestInProgressException while the CA is still being created, got {refusal!r}"
    )

    # Effect absent: an independent read confirms the CA has not silently skipped
    # ahead to ACTIVE behind the refused call's back.
    status_at_refusal = _describe_status(pca, arn)
    assert status_at_refusal in {"CREATING", "PENDING_CERTIFICATE"}, (
        f"expected the CA to still be CREATING or PENDING_CERTIFICATE right after "
        f"the refused call, got {status_at_refusal!r}"
    )

    # Restore / positive control: once the SAME CA leaves CREATING, the identical
    # call must now succeed.
    _poll_until(
        lambda: _describe_status(pca, arn),
        lambda s: s == "PENDING_CERTIFICATE",
        timeout_s=60.0, interval_s=2.0,
        description="CA reaching PENDING_CERTIFICATE",
    )
    csr = pca.get_certificate_authority_csr(CertificateAuthorityArn=arn).get("Csr")
    assert isinstance(csr, str) and csr.strip().startswith("-----BEGIN CERTIFICATE REQUEST-----"), (
        f"expected a real CSR PEM once the CA reached PENDING_CERTIFICATE, got {csr!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
