"""tag-resource-quota-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTagsToCertificate beyond the 50-tag quota raises TooManyTagsException and leaves the 50
    existing tags untouched; after freeing a slot the same call succeeds."""
    acm = ctx.client("acm")
    domain = f"{ctx.unique_name('sim2real-acm-quota')}.example.com"
    cert_arn = acm.request_certificate(DomainName=domain, ValidationMethod="DNS")["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    # TagResource rejects certificate ARNs, so certificate tagging uses AddTagsToCertificate.
    # Fill up to the 50-tag-per-resource quota (positive control: this must succeed).
    first_batch = [{"Key": f"k{i}", "Value": "v"} for i in range(49)]
    acm.add_tags_to_certificate(CertificateArn=cert_arn, Tags=first_batch)
    acm.add_tags_to_certificate(CertificateArn=cert_arn, Tags=[{"Key": "k49", "Value": "v"}])  # now exactly 50

    tags_at_quota = acm.list_tags_for_certificate(CertificateArn=cert_arn)["Tags"]
    assert len(tags_at_quota) == 50, f"expected exactly 50 tags at quota, got {len(tags_at_quota)}"

    # Attempting to add one more tag beyond the quota must be rejected.
    code, message = _error(
        lambda: acm.add_tags_to_certificate(CertificateArn=cert_arn, Tags=[{"Key": "k50", "Value": "v"}])
    )
    # ACM's certificate-tagging API (AddTagsToCertificate) reports quota violations via its
    # own "TooManyTagsException" error, not the generic ServiceQuotaExceededException used by
    # some other services' tagging APIs.
    assert code == "TooManyTagsException", f"expected TooManyTagsException, got {code}"
    expected_message = "The resultant tag set must not have more than 50 user tags."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The forbidden effect must be absent: still exactly 50 tags, no "k50" key present.
    tags_after = acm.list_tags_for_certificate(CertificateArn=cert_arn)["Tags"]
    tag_keys_after = {t["Key"] for t in tags_after}
    assert len(tags_after) == 50, f"tag count should remain 50 after rejected call, got {len(tags_after)}"
    assert "k50" not in tag_keys_after, "rejected tag key 'k50' must not have been applied"

    # Restore: freeing one slot under quota must let the identical call now succeed.
    acm.remove_tags_from_certificate(CertificateArn=cert_arn, Tags=[{"Key": "k0", "Value": "v"}])
    acm.add_tags_to_certificate(CertificateArn=cert_arn, Tags=[{"Key": "k50", "Value": "v"}])
    tags_final = acm.list_tags_for_certificate(CertificateArn=cert_arn)["Tags"]
    tag_keys_final = {t["Key"] for t in tags_final}
    assert len(tags_final) == 50, f"expected 50 tags after freeing a slot and retrying, got {len(tags_final)}"
    assert "k50" in tag_keys_final, "k50 must succeed once quota headroom exists"
    assert "k0" not in tag_keys_final, "k0 should have been removed by RemoveTagsFromCertificate"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
