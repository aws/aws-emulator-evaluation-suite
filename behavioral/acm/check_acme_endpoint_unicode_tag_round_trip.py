"""acme-endpoint-unicode-tag-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "acme-endpoint-unicode-tag-round-trip"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A unicode tag value (accented Latin, CJK, Greek) set via TagResource on an ACME endpoint
    is returned byte-identical by ListTagsForResource."""
    acm = ctx.client("acm")
    endpoint_arn, _ = _create_active_acme_endpoint(ctx, acm)

    tag_key = "sim2real-unicode-tag"
    # Tag.Value allows only \p{L}/\p{Z}/\p{N} plus "_.:/=+-@", so an emoji would be rejected.
    unicode_value = "Zürich-日本語-Ω-Café"
    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": tag_key, "Value": unicode_value}])
    ctx.on_cleanup(lambda: acm.untag_resource(ResourceArn=endpoint_arn, TagKeys=[tag_key]))

    tags = acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    matching = [t for t in tags if t["Key"] == tag_key]
    assert len(matching) == 1, f"expected exactly one tag with key {tag_key!r}, got {matching}"
    assert matching[0]["Value"] == unicode_value, (
        f"tag value not byte-identical: {matching[0]['Value']!r} != {unicode_value!r}"
    )


def _create_active_acme_endpoint(ctx, acm, timeout_s: float = 180.0, interval_s: float = 5.0):
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))

    deadline = time.monotonic() + timeout_s
    endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    while endpoint["Status"] == "CREATING" and time.monotonic() < deadline:
        time.sleep(interval_s)
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    if endpoint["Status"] != "ACTIVE":
        raise AssertionError(
            f"ACME endpoint never reached ACTIVE (status={endpoint['Status']}, "
            f"reason={endpoint.get('FailureReason')})"
        )
    return arn, endpoint["EndpointUrl"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
