"""tag-certificate-authority-reserved-prefix-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-certificate-authority-reserved-prefix-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

def _err(fn):
    """Call fn() and return (Error.Code, Error.Message); a successful call fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

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

# Reserved-prefix tag keys a direct (non-CloudFormation) caller must never be able to
# set. acm-pca allows ``aws:cloudformation:`` keys ONLY when the request is invoked by
# CloudFormation (aws:InvokedBy == cloudformation.amazonaws.com over a Forward Access
# Session), so a caller with ordinary credentials must still be rejected.
_RESERVED_TAG_KEYS = ("aws:reserved", "aws:cloudformation:stack-id")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagCertificateAuthority rejects reserved 'aws' prefix tag keys with InvalidTagException,
    including an ``aws:cloudformation:`` key sent by a direct caller, and never persists them."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)

    # positive control: an ordinary tag is accepted, so the negatives below are known
    # to test the reserved prefix specifically and not "every TagCertificateAuthority call".
    good_key = ctx.unique_name("sim2real-behav-goodtag-")
    pca.tag_certificate_authority(CertificateAuthorityArn=arn, Tags=[{"Key": good_key, "Value": "ok"}])
    tags_after_good = {t["Key"]: t["Value"] for t in pca.list_tags(CertificateAuthorityArn=arn)["Tags"]}
    assert tags_after_good.get(good_key) == "ok", f"positive control: {good_key} not applied, got {tags_after_good}"

    for key in _RESERVED_TAG_KEYS:
        code, message = _err(
            lambda key=key: pca.tag_certificate_authority(
                CertificateAuthorityArn=arn, Tags=[{"Key": key, "Value": "x"}]
            )
        )
        assert code == "InvalidTagException", f"{key}: {code}"
        assert message == (
            "Tags starting with 'aws' are categorized as AWS internal tags and cannot be used "
            "for tagging in ACM Private CA service."
        ), f"{key}: unexpected InvalidTagException message {message!r}"

        # effect absent: an independent read confirms the rejected key was never persisted
        tags_after_reject = {t["Key"] for t in pca.list_tags(CertificateAuthorityArn=arn)["Tags"]}
        assert key not in tags_after_reject, f"{key} present after rejected TagCertificateAuthority"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
