"""tag-certificate-authority-invalid-tag-key-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-certificate-authority-invalid-tag-key-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagCertificateAuthority rejects a tag key with characters outside the allowed set
    (letters, digits, spaces, _.:/=+-@) instead of silently sanitizing and applying it."""
    acm = ctx.client("acm-pca")
    ca_arn = _create_ca(ctx)
    bad_key = "bad#tag!"

    def _tag_with_bad_key():
        acm.tag_certificate_authority(CertificateAuthorityArn=ca_arn, Tags=[{"Key": bad_key, "Value": "x"}])

    code, message = _error(_tag_with_bad_key)
    # AWS rejects a disallowed tag key with the generic ValidationException (a
    # shape-level pattern constraint), not the service-specific InvalidTagException.
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)"
    ), f"unexpected ValidationException message: {message!r}"

    # effect absent: the disallowed key (mangled or as-is) was not persisted
    tags_after_reject = {t["Key"]: t["Value"] for t in acm.list_tags(CertificateAuthorityArn=ca_arn)["Tags"]}
    assert bad_key not in tags_after_reject
    assert "badtag" not in tags_after_reject  # a plausible sanitized/stripped variant

    # positive control: a valid tag key/value pair is applied successfully
    good_key = "Environment"
    acm.tag_certificate_authority(CertificateAuthorityArn=ca_arn, Tags=[{"Key": good_key, "Value": "test"}])
    ctx.on_cleanup(lambda: _untag_safely(ctx, ca_arn, good_key))
    tags_after_accept = {t["Key"]: t["Value"] for t in acm.list_tags(CertificateAuthorityArn=ca_arn)["Tags"]}
    assert tags_after_accept.get(good_key) == "test"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_ca(ctx, key_algorithm="RSA_2048", signing_algorithm="SHA256WITHRSA", ca_type="ROOT"):
    acm = ctx.client("acm-pca")
    cn = ctx.unique_name("sim2real-pca-")
    resp = acm.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": key_algorithm,
            "SigningAlgorithm": signing_algorithm,
            "Subject": {"CommonName": cn},
        },
        CertificateAuthorityType=ca_type,
    )
    arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, arn))
    _wait_for_csr_ready(ctx, arn)
    return arn


def _delete_ca(ctx, arn):
    acm = ctx.client("acm-pca")
    try:
        acm.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_csr_ready(ctx, arn, timeout_s=90.0, interval_s=2.0):
    acm = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = acm.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if status in ("PENDING_CERTIFICATE", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError("CA never left CREATING state")


def _untag_safely(ctx, ca_arn, key):
    acm = ctx.client("acm-pca")
    try:
        acm.untag_certificate_authority(CertificateAuthorityArn=ca_arn, Tags=[{"Key": key}])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
