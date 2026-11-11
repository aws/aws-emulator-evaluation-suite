"""portal-product-sharing-policy-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "portal-product-sharing-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPortalProductSharingPolicy creates a policy retrievable via Get; DeletePortalProductSharingPolicy
    resets the resource-based policy back to its empty ("{}") default rather than removing the resource
    (GetPortalProductSharingPolicy keeps succeeding — the portal product itself still exists)."""
    apigw = ctx.client("apigatewayv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = apigw.meta.region_name

    product_id = apigw.create_portal_product(DisplayName=ctx.unique_name("sim2real-sp-prod-"))[
        "PortalProductId"
    ]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: apigw.delete_portal_product(PortalProductId=product_id))
    )

    product_arn = f"arn:aws:apigateway:{region}:{account_id}:/portalproducts/{product_id}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOwnAccount",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "apigateway:GetPortalProduct",
                "Resource": product_arn,
            }
        ],
    }
    policy_document = json.dumps(policy)

    try:
        apigw.put_portal_product_sharing_policy(
            PortalProductId=product_id, PolicyDocument=policy_document
        )
    except ClientError as exc:
        raise AssertionError(f"PutPortalProductSharingPolicy failed: {exc.response['Error']}") from exc
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_portal_product_sharing_policy(PortalProductId=product_id)
        )
    )

    got = apigw.get_portal_product_sharing_policy(PortalProductId=product_id)
    assert got["PortalProductId"] == product_id, (
        f"expected GetPortalProductSharingPolicy to echo PortalProductId={product_id!r}, "
        f"got {got['PortalProductId']!r}"
    )
    got_policy = json.loads(got["PolicyDocument"])
    assert got_policy == policy, f"expected stored policy {policy!r}, got {got_policy!r}"

    apigw.delete_portal_product_sharing_policy(PortalProductId=product_id)
    after_delete = _poll_until(
        lambda: apigw.get_portal_product_sharing_policy(PortalProductId=product_id),
        lambda resp: resp.get("PolicyDocument") == "{}",
    )
    assert after_delete["PolicyDocument"] == "{}", (
        f"expected the policy to reset to the empty '{{}}' default after delete, "
        f"got {after_delete['PolicyDocument']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    import time

    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
