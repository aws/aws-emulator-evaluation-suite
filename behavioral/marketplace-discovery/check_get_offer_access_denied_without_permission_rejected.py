"""get-offer-access-denied-without-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-offer-access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c5", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal with no policy gets AccessDeniedException from GetOffer (IAM implicit deny) while the
    default caller reads the same offerId, and granting the principal an explicit Allow for
    aws-marketplace:GetOffer makes the identical call succeed."""
    md = ctx.client("marketplace-discovery")
    offer = _discover_offer(ctx)
    if offer is None:
        raise AssertionError(
            "no product in the sampled catalog had a purchase option with a resolvable offer "
            "visible to this caller"
        )
    offer_id = offer["offer_id"]

    # Positive control: the privileged (ambient) credentials can read this
    # offer.
    control = md.get_offer(offerId=offer_id)
    assert control["offerId"] == offer_id

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-marketplace-noperm-offer-")
    policy_name = "allow-get-offer"

    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    # Re-signed through ctx.client(creds=...) so the second hop keeps THIS target's
    # endpoint -- a hand-rolled boto3.client() here would reach real AWS on an emulator
    # run and the check would grade the wrong target.
    unprivileged = ctx.client(
        "marketplace-discovery",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    # A brand-new principal with NO attached policy is denied by ordinary IAM implicit-deny.
    # New credentials are eventually consistent -- poll for the steady-state decision rather
    # than asserting on the first attempt.
    code, message = _poll_for_denial(unprivileged, offer_id, timeout_s=min(90.0, ctx.time_left()), interval_s=2.0)
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a principal with no attached policy, got {code!r}"
    )
    assert message != _KEY_NOT_YET_VALID, (
        f"the new key never propagated within the poll window; last answer {message!r}"
    )

    # Restore: granting the identical principal an explicit Allow for
    # aws-marketplace:GetOffer makes the identical call succeed -- proving the earlier
    # denial was about missing permission, not something else about the minted principal
    # or the offer itself.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "aws-marketplace:GetOffer", "Resource": "*"}
        ],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: _drop_user_policy(iam, user_name, policy_name))

    restored = _poll_for_success(unprivileged, offer_id, timeout_s=min(90.0, ctx.time_left()), interval_s=2.0)
    assert restored["offerId"] == offer_id, (
        f"granting an explicit Allow must restore GetOffer for the same principal/offerId; "
        f"got {restored!r}"
    )


# A new access key answers with this denial until IAM has propagated it; it is not the
# authorization decision the check asserts, so the poll keeps waiting past it.
_KEY_NOT_YET_VALID = "The security token included in the request is invalid."


def _poll_for_denial(client, offer_id, *, timeout_s: float, interval_s: float):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = last_message = None
    while time.monotonic() < deadline:
        try:
            client.get_offer(offerId=offer_id)
            last_code = last_message = None
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            last_message = e.response["Error"].get("Message")
            if last_code == "AccessDeniedException" and last_message != _KEY_NOT_YET_VALID:
                return last_code, last_message
        time.sleep(interval_s)
    return last_code, last_message


def _poll_for_success(client, offer_id, *, timeout_s: float, interval_s: float):
    """After the Allow is granted, poll until the identical call succeeds."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return client.get_offer(offerId=offer_id)
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
        time.sleep(interval_s)
    raise AssertionError(
        f"GetOffer never succeeded after the Allow was granted; last error code {last_code!r}"
    )


def _drop_user_policy(iam, user_name, policy_name):
    """Teardown-only: tolerate the policy already being gone."""
    from botocore.exceptions import ClientError

    try:
        iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _discover_offer(ctx):
    md = ctx.client("marketplace-discovery")
    search = md.search_listings(maxResults=25)
    product_ids: list[str] = []
    for summary in search["listingSummaries"]:
        for assoc in summary["associatedEntities"]:
            product = assoc.get("product")
            if product and product["productId"] not in product_ids:
                product_ids.append(product["productId"])

    for product_id in product_ids[:10]:
        try:
            purchase = md.list_purchase_options(
                filters=[{"filterType": "PRODUCT_ID", "filterValues": [product_id]}],
                maxResults=10,
            )
        except Exception:
            continue
        for option in purchase.get("purchaseOptions", []):
            for assoc in option.get("associatedEntities", []):
                offer_info = assoc.get("offer")
                if offer_info:
                    return {"product_id": product_id, "offer_id": offer_info["offerId"]}
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
