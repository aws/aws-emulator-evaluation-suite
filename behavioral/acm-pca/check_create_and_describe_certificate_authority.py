"""create-and-describe-certificate-authority."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-and-describe-certificate-authority"
GROUP = 'lifecycle'
SERVICES = ['acm-pca']

def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]

def _wait_for_status_change(ctx, ca_arn, status, timeout_s=90.0, interval_s=2.0):
    """Poll until the CA leaves CREATING and return its resting status."""
    deadline = time.monotonic() + timeout_s
    while status == "CREATING":
        if time.monotonic() > deadline:
            raise AssertionError(f"CA {ca_arn} still CREATING after {timeout_s}s")
        time.sleep(interval_s)
        status = _describe(ctx, ca_arn)["Status"]
    return status

def _delete_ca(ctx, ca_arn):
    try:
        ctx.client("acm-pca").delete_certificate_authority(
            CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCertificateAuthority mints a ROOT CA; DescribeCertificateAuthority
    echoes its configuration, and the CA settles in PENDING_CERTIFICATE (never
    ACTIVE without an installed cert)."""
    arn = _create_ca(ctx)
    ca = _describe(ctx, arn)

    assert ca["Arn"] == arn, ca
    assert ca["Type"] == "ROOT", ca["Type"]
    assert ca["UsageMode"] == "SHORT_LIVED_CERTIFICATE", ca.get("UsageMode")
    cfg = ca["CertificateAuthorityConfiguration"]
    assert cfg["KeyAlgorithm"] == "RSA_2048", cfg
    assert cfg["SigningAlgorithm"] == "SHA256WITHRSA", cfg
    # A brand-new CA with no certificate installed rests in PENDING_CERTIFICATE.
    status = _wait_for_status_change(ctx, arn, ca["Status"])
    assert status == "PENDING_CERTIFICATE", status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
