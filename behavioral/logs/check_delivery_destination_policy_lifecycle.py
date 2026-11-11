"""delivery-destination-policy-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delivery-destination-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDeliveryDestinationPolicy attaches a resource policy retrievable via
    GetDeliveryDestinationPolicy and removable via DeleteDeliveryDestinationPolicy."""
    logs = ctx.client("logs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    log_group_name, log_group_arn = _create_log_group(ctx, "sim2real-behav-ddplg-")
    dest_name = ctx.unique_name("sim2real-behav-ddstp-")
    logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_destination(name=dest_name)))

    region = ctx.region
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowLogDeliveryActions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "logs:CreateDelivery",
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:delivery-source:*",
                    f"arn:aws:logs:{region}:{account_id}:delivery:*",
                    f"arn:aws:logs:{region}:{account_id}:delivery-destination:*",
                ],
            }
        ],
    }

    put_resp = logs.put_delivery_destination_policy(
        deliveryDestinationName=dest_name, deliveryDestinationPolicy=json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: logs.delete_delivery_destination_policy(deliveryDestinationName=dest_name)
        )
    )
    returned_doc = json.loads(put_resp["policy"]["deliveryDestinationPolicy"])
    assert returned_doc["Statement"][0]["Action"] == "logs:CreateDelivery"

    got = logs.get_delivery_destination_policy(deliveryDestinationName=dest_name)
    got_doc = json.loads(got["policy"]["deliveryDestinationPolicy"])
    assert got_doc["Statement"][0]["Sid"] == "AllowLogDeliveryActions"
    assert set(got_doc["Statement"][0]["Resource"]) == set(policy_doc["Statement"][0]["Resource"])

    logs.delete_delivery_destination_policy(deliveryDestinationName=dest_name)

    # A destination with no policy attached reads back as an empty Get (200), never a
    # ResourceNotFoundException -- that code is reserved for a missing *destination*, not a
    # missing policy on one that exists.
    after_delete = logs.get_delivery_destination_policy(deliveryDestinationName=dest_name)
    policy_after = after_delete.get("policy", {}) or {}
    assert not policy_after.get("deliveryDestinationPolicy"), (
        f"expected no delivery destination policy after delete, got {after_delete}"
    )

    # The policy is dead, not just absent from one read: deleting it again raises the same
    # ResourceNotFoundException a destination that never had a policy would give, never a
    # resurfaced document or a silent no-op success.
    from botocore.exceptions import ClientError

    try:
        logs.delete_delivery_destination_policy(deliveryDestinationName=dest_name)
        raise AssertionError("expected ResourceNotFoundException re-deleting an already-absent policy")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException re-deleting an already-absent policy, got {code}"
        )
        message = e.response["Error"].get("Message", "")
        expected = "Delivery Destination Policy does not exist for this Delivery Destination."
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The delivery destination itself must survive the deletion of only its policy.
    still_there = logs.get_delivery_destination(name=dest_name)
    assert still_there["deliveryDestination"]["name"] == dest_name


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


def _create_log_group(ctx, prefix: str):
    logs = ctx.client("logs")
    name = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_log_group(logGroupName=name)))
    resp = logs.describe_log_groups(logGroupNamePrefix=name)
    arn = resp["logGroups"][0]["arn"]
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
