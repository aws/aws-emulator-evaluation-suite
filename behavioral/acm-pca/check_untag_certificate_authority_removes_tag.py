"""untag-certificate-authority-removes-tag."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-certificate-authority-removes-tag"
GROUP = 'tags'
SERVICES = ['acm-pca']

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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagCertificateAuthority removes exactly the specified tag, leaving others."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    keep = ctx.unique_name("sim2real-behav-keep-")
    drop = ctx.unique_name("sim2real-behav-drop-")

    pca.tag_certificate_authority(
        CertificateAuthorityArn=arn,
        Tags=[{"Key": keep, "Value": "pki"}, {"Key": drop, "Value": "probe"}],
    )
    pca.untag_certificate_authority(
        CertificateAuthorityArn=arn, Tags=[{"Key": drop, "Value": "probe"}]
    )
    tags = pca.list_tags(CertificateAuthorityArn=arn)["Tags"]
    keys = {t["Key"] for t in tags}
    assert keep in keys, f"kept tag {keep!r} missing after untag: {tags}"
    assert drop not in keys, f"untagged key still present: {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
