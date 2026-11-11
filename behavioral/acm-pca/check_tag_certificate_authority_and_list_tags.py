"""tag-certificate-authority-and-list-tags."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-certificate-authority-and-list-tags"
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
    """TagCertificateAuthority tags are visible via ListTags."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    key = ctx.unique_name("sim2real-behav-tagkey-")

    pca.tag_certificate_authority(
        CertificateAuthorityArn=arn, Tags=[{"Key": key, "Value": "probe"}]
    )
    tags = pca.list_tags(CertificateAuthorityArn=arn)["Tags"]
    mine = [t for t in tags if t["Key"] == key]
    assert mine, f"tag {key} not found in {tags}"
    assert mine[0]["Value"] == "probe", f"tag {key} value changed: expected 'probe' got {mine[0]['Value']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
