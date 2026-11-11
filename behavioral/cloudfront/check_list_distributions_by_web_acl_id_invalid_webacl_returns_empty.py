"""list-distributions-by-web-acl-id-invalid-webacl-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-distributions-by-web-acl-id-invalid-webacl-returns-empty"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByWebACLId accepts the malformed WebACLId "arn:aws:wafv2" as a filter that matches
    0 distributions, not a validation error, and the "null" sentinel query returns the same Quantity
    before and after it."""
    cf = ctx.client("cloudfront")

    # documented sentinel: distributions that aren't associated with a web ACL.
    sentinel = cf.list_distributions_by_web_acl_id(WebACLId="null")
    assert "DistributionList" in sentinel, (
        f"expected a DistributionList key in the 'null'-sentinel response, got keys {sorted(sentinel)}"
    )

    # a value that is neither a valid WAF Classic id nor a well-formed WAFV2 ARN is still
    # accepted - CloudFront does not validate the shape of WebACLId for this list operation,
    # it just filters and finds no match.
    malformed = cf.list_distributions_by_web_acl_id(WebACLId="arn:aws:wafv2")
    quantity = malformed["DistributionList"]["Quantity"]
    assert quantity == 0, (
        f"expected Quantity == 0 for the syntactically-invalid WebACLId 'arn:aws:wafv2' "
        f"(CloudFront does not validate WebACLId shape for this operation), got Quantity={quantity}"
    )

    # the malformed request must not have perturbed the well-formed sentinel query.
    still_ok = cf.list_distributions_by_web_acl_id(WebACLId="null")
    assert "DistributionList" in still_ok, (
        f"expected the 'null'-sentinel query to still succeed after the malformed WebACLId "
        f"request, got keys {sorted(still_ok)}"
    )
    assert still_ok["DistributionList"].get("Quantity") == sentinel["DistributionList"].get(
        "Quantity"
    ), (
        "expected the malformed WebACLId request to leave the 'null'-sentinel Quantity "
        f"unperturbed: before={sentinel['DistributionList'].get('Quantity')!r} "
        f"after={still_ok['DistributionList'].get('Quantity')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
