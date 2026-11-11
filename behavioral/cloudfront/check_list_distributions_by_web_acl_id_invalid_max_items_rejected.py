"""list-distributions-by-web-acl-id-invalid-max-items-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-distributions-by-web-acl-id-invalid-max-items-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByWebACLId with a non-numeric MaxItems is refused with InvalidArgument and the
    exact message, while the "null" sentinel returns a DistributionList and a well-formed but
    nonexistent web ACL ARN matches 0 distributions."""
    cf = ctx.client("cloudfront")

    # CloudFront does not format-validate WebACLId for this API (an unknown value matches
    # nothing); the documented InvalidArgument fires on the pagination params instead.
    code, message = _error_code_and_message(
        lambda: cf.list_distributions_by_web_acl_id(WebACLId="null", MaxItems="not-a-number")
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    assert message == "MaxItems must be a non-zero positive integer.", f"unexpected message {message!r}"

    # Positive control: the documented "null" sentinel is a well-formed request and succeeds.
    resp = cf.list_distributions_by_web_acl_id(WebACLId="null")
    assert "DistributionList" in resp, f"expected DistributionList in response, got keys {list(resp)!r}"
    quantity = resp["DistributionList"].get("Quantity")
    assert isinstance(quantity, int), f"expected DistributionList.Quantity to be an int, got {quantity!r}"

    # A syntactically opaque, definitely-nonexistent WebACLId is accepted (not rejected) and
    # simply matches no distributions -- documenting the actual (permissive) contract rather
    # than asserting a rejection that real AWS does not perform.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resp2 = cf.list_distributions_by_web_acl_id(
        WebACLId=f"arn:aws:wafv2:us-east-1:{account_id}:global/webacl/does-not-exist/00000000-0000-0000-0000-000000000000"
    )
    quantity2 = resp2["DistributionList"]["Quantity"]
    assert quantity2 == 0, f"expected 0 distributions for a nonexistent WebACLId, got Quantity={quantity2!r}"
    items2 = resp2["DistributionList"].get("Items", [])
    assert items2 == [], f"expected no Items for a nonexistent WebACLId, got {items2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
