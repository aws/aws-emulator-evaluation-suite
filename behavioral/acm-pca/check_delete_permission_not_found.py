"""delete-permission-not-found."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-permission-not-found"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']

_NO_PERMISSION_MESSAGE = "Could not find a Permission for specified CA."

def _err(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")

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
    """DeletePermission for a principal without a permission returns ResourceNotFoundException,
    both before any grant and again after a real grant was created, listed, and deleted."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    principal = "acm.amazonaws.com"

    never_granted = _err(
        lambda: pca.delete_permission(CertificateAuthorityArn=arn, Principal=principal)
    )
    assert never_granted == ("ResourceNotFoundException", _NO_PERMISSION_MESSAGE), never_granted

    # Positive control: a real grant round-trips, so not-found is not a blanket rejection.
    actions = ["IssueCertificate", "GetCertificate", "ListPermissions"]
    pca.create_permission(CertificateAuthorityArn=arn, Principal=principal, Actions=actions)
    granted = pca.list_permissions(CertificateAuthorityArn=arn)["Permissions"]
    assert any(p.get("Principal") == principal for p in granted), (
        f"CreatePermission not visible via ListPermissions: {granted}"
    )

    pca.delete_permission(CertificateAuthorityArn=arn, Principal=principal)
    remaining = pca.list_permissions(CertificateAuthorityArn=arn)["Permissions"]
    assert not any(p.get("Principal") == principal for p in remaining), (
        f"permission still listed after a delete that reported success: {remaining}"
    )

    double_delete = _err(
        lambda: pca.delete_permission(CertificateAuthorityArn=arn, Principal=principal)
    )
    assert double_delete == ("ResourceNotFoundException", _NO_PERMISSION_MESSAGE), double_delete


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
