"""tag-resource-unicode-value-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resource-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A multi-byte unicode tag value within the Tag.Value charset round-trips unchanged through
    TagResource/ListTagsForResource on an ACME endpoint; an emoji value is rejected, adding no
    tag."""
    acm = ctx.client("acm")

    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)))

    _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )

    unicode_value = "café-テスト-Ω"
    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real-unicode", "Value": unicode_value}])

    tags = acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    assert tag_map.get("sim2real-unicode") == unicode_value, (
        f"unicode tag value not round-tripped: expected {unicode_value!r}, "
        f"got {tag_map.get('sim2real-unicode')!r}"
    )

    # boundary control: the Tag.Value pattern only covers \p{L}/\p{Z}/\p{N} plus
    # "_.:/=+-@" -- an emoji (category "So") is OUTSIDE that charset and TagResource
    # rejects it with ValidationException, leaving no partial/sanitized tag behind.
    disallowed_value = "rocket-\U0001F680-emoji"
    from botocore.exceptions import ClientError

    try:
        acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "sim2real-bad-tag", "Value": disallowed_value}])
        raise AssertionError("TagResource accepted a tag value containing an emoji outside the allowed charset")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ValidationException", (
            f"expected ValidationException for an out-of-charset tag value, "
            f"got {exc.response['Error']['Code']!r}"
        )
        expected_message = (
            "1 validation error detected: Value of the input at 'tags.1.member.value' failed to "
            "satisfy constraint: Member must satisfy regular expression pattern: "
            "([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)"
        )
        message = exc.response["Error"].get("Message")
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tags_after_reject = acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    assert "sim2real-bad-tag" not in {t["Key"] for t in tags_after_reject}, (
        "rejected TagResource call still left a partial/sanitized tag behind"
    )


def _safe_call(fn) -> None:
    fn()


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

