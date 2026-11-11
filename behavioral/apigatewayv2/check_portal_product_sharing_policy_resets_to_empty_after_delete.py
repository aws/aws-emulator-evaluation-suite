"""portal-product-sharing-policy-resets-to-empty-after-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "portal-product-sharing-policy-resets-to-empty-after-delete"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]
TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeletePortalProductSharingPolicy, Get returns an empty "{}" policy, not a 404 or
    the stale policy; putting the policy again on the same product succeeds."""
    apigw = ctx.client("apigatewayv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = apigw.meta.region_name
    product_id = _create_portal_product(ctx, apigw)
    resource_arn = f"arn:aws:apigateway:{region}:{account_id}:/portalproducts/{product_id}"

    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": "apigateway:GetPortalProduct",
                    "Resource": [resource_arn, f"{resource_arn}/*"],
                }
            ],
        }
    )
    apigw.put_portal_product_sharing_policy(PortalProductId=product_id, PolicyDocument=policy)

    got = apigw.get_portal_product_sharing_policy(PortalProductId=product_id)
    _assert_policy_matches(got["PolicyDocument"], resource_arn, account_id)

    apigw.delete_portal_product_sharing_policy(PortalProductId=product_id)

    result = _poll_until(
        lambda: _call(
            lambda: apigw.get_portal_product_sharing_policy(PortalProductId=product_id)
        ),
        lambda r: r["code"] is not None
        or r["value"]["PolicyDocument"] != policy,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert result["code"] is None, f"expected a successful reset GET, got code={result['code']!r}"
    assert result["value"]["PolicyDocument"] == "{}", (
        f"expected the policy to reset to an empty document after delete, "
        f"got {result['value']['PolicyDocument']!r}"
    )





    # positive control: putting the policy again on the same still-existing product succeeds
    apigw.put_portal_product_sharing_policy(PortalProductId=product_id, PolicyDocument=policy)
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_portal_product_sharing_policy(PortalProductId=product_id)
        )
    )
    got2 = apigw.get_portal_product_sharing_policy(PortalProductId=product_id)
    _assert_policy_matches(got2["PolicyDocument"], resource_arn, account_id)


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _call(fn):
    from botocore.exceptions import ClientError

    try:
        return {"code": None, "value": fn()}
    except ClientError as e:
        return {"code": e.response["Error"]["Code"], "value": e.response["Error"]}



def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")



def _assert_policy_matches(policy_document, resource_arn, account_id):
    """AWS may reformat the stored policy (e.g. wrap scalars into lists, add a Sid,
    reorder keys) so compare the substantive content rather than byte-for-byte."""
    doc = json.loads(policy_document)
    assert doc["Version"] == "2012-10-17"
    assert len(doc["Statement"]) == 1
    stmt = doc["Statement"][0]
    assert stmt["Effect"] == "Allow"

    action = stmt["Action"]
    actions = action if isinstance(action, list) else [action]
    assert "apigateway:GetPortalProduct" in actions

    resource = stmt["Resource"]
    resources = set(resource if isinstance(resource, list) else [resource])
    assert resources == {resource_arn, f"{resource_arn}/*"}, resources

    principal = stmt["Principal"]["AWS"]
    principals = principal if isinstance(principal, list) else [principal]
    # AWS may normalize a bare account id into an ARN form (e.g. "...:root")
    assert any(account_id in p for p in principals), principals



def _create_portal_product(ctx, apigw):
    product_id = apigw.create_portal_product(
        DisplayName=ctx.unique_name("sim2real-behav-product-"), Tags=TAGS
    )["PortalProductId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: apigw.delete_portal_product(PortalProductId=product_id))
    )
    return product_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
