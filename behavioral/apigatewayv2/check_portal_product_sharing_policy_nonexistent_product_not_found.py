"""portal-product-sharing-policy-nonexistent-product-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "portal-product-sharing-policy-nonexistent-product-not-found"
GROUP = "portal-products"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPortalProductSharingPolicy, PutPortalProductSharingPolicy and
    DeletePortalProductSharingPolicy on a portal product id that was deleted all fail
    NotFoundException, while the same three calls succeed on a sibling product that still exists."""
    agw = ctx.client("apigatewayv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = agw.meta.region_name

    sibling_id = agw.create_portal_product(
        DisplayName=ctx.unique_name("sim2real-behav-pp-ok-"), Tags=TAGS
    )["PortalProductId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: agw.delete_portal_product(PortalProductId=sibling_id)))

    doomed_id = agw.create_portal_product(
        DisplayName=ctx.unique_name("sim2real-behav-pp-dead-"), Tags=TAGS
    )["PortalProductId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: agw.delete_portal_product(PortalProductId=doomed_id)))
    agw.delete_portal_product(PortalProductId=doomed_id)

    def policy_for(product_id: str) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "apigateway:GetPortalProduct",
                        "Resource": f"arn:aws:apigateway:{region}:{account_id}:/portalproducts/{product_id}",
                    }
                ],
            }
        )

    expected_message = f"Product not found in account {account_id} with id {doomed_id}"

    get_code, get_message = _error(
        lambda: agw.get_portal_product_sharing_policy(PortalProductId=doomed_id)
    )
    assert get_code == "NotFoundException", (
        f"GetPortalProductSharingPolicy on a deleted product: expected NotFoundException, "
        f"got {get_code}: {get_message!r}"
    )
    assert get_message == expected_message, (
        f"GetPortalProductSharingPolicy on a deleted product: unexpected message {get_message!r}"
    )

    put_code, put_message = _error(
        lambda: agw.put_portal_product_sharing_policy(
            PortalProductId=doomed_id, PolicyDocument=policy_for(doomed_id)
        )
    )
    assert put_code == "NotFoundException", (
        f"PutPortalProductSharingPolicy on a deleted product: expected NotFoundException, "
        f"got {put_code}: {put_message!r}"
    )
    assert put_message == expected_message, (
        f"PutPortalProductSharingPolicy on a deleted product: unexpected message {put_message!r}"
    )

    delete_code, delete_message = _error(
        lambda: agw.delete_portal_product_sharing_policy(PortalProductId=doomed_id)
    )
    assert delete_code == "NotFoundException", (
        f"DeletePortalProductSharingPolicy on a deleted product: expected NotFoundException, "
        f"got {delete_code}: {delete_message!r}"
    )
    assert delete_message == expected_message, (
        f"DeletePortalProductSharingPolicy on a deleted product: unexpected message {delete_message!r}"
    )

    # positive control: the same three calls succeed on the sibling product that still exists.
    agw.put_portal_product_sharing_policy(PortalProductId=sibling_id, PolicyDocument=policy_for(sibling_id))
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: agw.delete_portal_product_sharing_policy(PortalProductId=sibling_id))
    )
    got = agw.get_portal_product_sharing_policy(PortalProductId=sibling_id)
    assert json.loads(got["PolicyDocument"]) == json.loads(policy_for(sibling_id)), (
        f"positive control: expected the just-set policy, got {got['PolicyDocument']!r}"
    )
    agw.delete_portal_product_sharing_policy(PortalProductId=sibling_id)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
