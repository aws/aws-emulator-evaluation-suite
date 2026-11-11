"""list-distributions-by-web-acl-id-malformed-webacl-id-silently-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-distributions-by-web-acl-id-malformed-webacl-id-silently-accepted"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByWebACLId does not validate WebACLId shape: malformed ids match zero
    distributions instead of raising InvalidWebACLId, and the "null" sentinel still succeeds."""
    cf = ctx.client("cloudfront")

    for malformed_web_acl_id in (
        "not-a-valid-webacl-id!!",
        "arn:aws:wafv2",
        "arn:aws:iam::123456789012:role/NotAWebACL",
    ):
        resp = cf.list_distributions_by_web_acl_id(WebACLId=malformed_web_acl_id)
        assert "DistributionList" in resp, (
            f"expected a DistributionList envelope even for malformed WebACLId "
            f"{malformed_web_acl_id!r}, got keys {sorted(resp)}"
        )
        items = resp["DistributionList"].get("Items", [])
        assert isinstance(items, list), (
            f"expected Items to be a list for malformed WebACLId "
            f"{malformed_web_acl_id!r}, got {type(items)!r}"
        )
        assert items == [], (malformed_web_acl_id, items)

    # Positive control: same operation, the documented "null" sentinel succeeds
    # and returns distributions that aren't associated with any web ACL.
    null_resp = cf.list_distributions_by_web_acl_id(WebACLId="null")
    assert "DistributionList" in null_resp, (
        f"expected the 'null' sentinel to succeed with a DistributionList envelope, "
        f"got keys {sorted(null_resp)}"
    )
    null_items = null_resp["DistributionList"].get("Items", [])
    assert isinstance(null_items, list), (
        f"expected Items to be a list for the 'null' sentinel, got {type(null_items)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

