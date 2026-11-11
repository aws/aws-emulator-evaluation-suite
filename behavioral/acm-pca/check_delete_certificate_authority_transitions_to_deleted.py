"""delete-certificate-authority-transitions-to-deleted."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-certificate-authority-transitions-to-deleted"
GROUP = 'lifecycle'
SERVICES = ['acm-pca']

# A DELETED (soft-deleted) CA stays addressable through
# DescribeCertificateAuthority and refuses mutation with InvalidStateException rather than accepting
# it or 404ing.
_EXPECTED_DELETED_STATE_REJECTION = "InvalidStateException"

def _err_resp(fn):
    """Call fn(); return the full botocore error response if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response
    return None

def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]

def _delete_ca(ctx, ca_arn):
    """Best-effort teardown: DeleteCertificateAuthority is refused with
    InvalidStateException while the CA is still CREATING, so poll it out of that
    state first. Safe to call even when run() already deleted the CA -- a repeat
    delete is an idempotent no-op on real AWS, not a refusal."""
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            status = _describe(ctx, ca_arn).get("Status")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status != "CREATING":
            break
        time.sleep(2)
    try:
        pca.delete_certificate_authority(
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
        "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
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

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCertificateAuthority on a never-activated CA succeeds and moves the CA
    into DELETED (soft delete, restorable) rather than issuing a cert or erroring, and
    that DELETED state is not cosmetic: a mutation on it is refused, not accepted."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)

    # A CA is born CREATING; DeleteCertificateAuthority with
    # PermanentDeletionTimeInDays requires it to have reached PENDING_CERTIFICATE
    # (or DISABLED). Wait for the create to settle before deleting.
    status = None
    for _ in range(30):
        status = _describe(ctx, arn)["Status"]
        if status in ("PENDING_CERTIFICATE", "DISABLED"):
            break
        time.sleep(1)
    else:
        raise AssertionError(f"CA did not leave CREATING within 30s, last status {status!r}")

    pca.delete_certificate_authority(
        CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7
    )

    # Real acm-pca soft-deletes: the ARN stays addressable through an independent
    # read and reports Status=DELETED (see _EXPECTED_DELETED_STATE_REJECTION above).
    ca = _describe(ctx, arn)
    assert ca["Status"] == "DELETED", ca["Status"]

    # Gone-and-unusable: the DELETED state must actually block a mutation, not just
    # flip a status word while a write still goes through underneath it.
    err = _err_resp(lambda: pca.tag_certificate_authority(
        CertificateAuthorityArn=arn, Tags=[{"Key": "sim2real-post-delete", "Value": "1"}]
    ))
    assert err is not None, "tagging a DELETED certificate authority must be refused"
    code = err.get("Error", {}).get("Code")
    assert code == _EXPECTED_DELETED_STATE_REJECTION, code
    message = err.get("Error", {}).get("Message")
    expected = "The certificate authority is in the DELETED state and must be restored to complete this action."
    assert message == expected, message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
