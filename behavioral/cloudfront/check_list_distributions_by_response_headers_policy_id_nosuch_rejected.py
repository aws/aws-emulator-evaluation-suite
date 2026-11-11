"""list-distributions-by-response-headers-policy-id-nosuch-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-distributions-by-response-headers-policy-id-nosuch-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByResponseHeadersPolicyId for an unknown (but well-formed) policy id
    is rejected with NoSuchResponseHeadersPolicy, while the same call against a real,
    freshly created (and unused) policy id succeeds.
    """
    cf = ctx.client("cloudfront")
    policy_id, etag = _create_response_headers_policy(ctx)

    ok = cf.list_distributions_by_response_headers_policy_id(ResponseHeadersPolicyId=policy_id)
    quantity = ok["DistributionIdList"]["Quantity"]
    assert quantity == 0, f"expected 0 distributions for an unused real policy, got {quantity}"

    code, message = _error_code_and_message(
        lambda: cf.list_distributions_by_response_headers_policy_id(ResponseHeadersPolicyId=str(uuid.uuid4()))
    )
    assert code == "NoSuchResponseHeadersPolicy", f"expected NoSuchResponseHeadersPolicy, got {code!r}"
    assert message == "The specified response headers policy does not exist.", f"unexpected message {message!r}"

    # the nonexistent lookup must not have created a phantom association on the real policy.
    still_empty = cf.list_distributions_by_response_headers_policy_id(ResponseHeadersPolicyId=policy_id)
    still_quantity = still_empty["DistributionIdList"]["Quantity"]
    assert still_quantity == 0, f"expected 0 distributions for the real policy after the rejected lookup, got {still_quantity}"


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected NoSuchResponseHeadersPolicy rejection, but the call succeeded and returned {result!r}")


def _create_response_headers_policy(ctx):
    cf = ctx.client("cloudfront")
    resp = cf.create_response_headers_policy(
        ResponseHeadersPolicyConfig={
            "Name": ctx.unique_name("sim2real-cf-rhp-"),
            "Comment": "sim2real behavioral fixture",
            "CustomHeadersConfig": {
                "Quantity": 1,
                "Items": [
                    {"Header": "x-sim2real-behav", "Value": "fixture", "Override": True}
                ],
            },
        }
    )
    policy_id = resp["ResponseHeadersPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_response_headers_policy(ctx, policy_id))
    return policy_id, resp["ETag"]


def _delete_response_headers_policy(ctx, policy_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_response_headers_policy(Id=policy_id)
        cf.delete_response_headers_policy(Id=policy_id, IfMatch=got["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResponseHeadersPolicy":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
