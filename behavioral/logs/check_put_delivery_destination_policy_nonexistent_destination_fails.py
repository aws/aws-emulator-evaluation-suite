"""put-delivery-destination-policy-nonexistent-destination-fails."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-delivery-destination-policy-nonexistent-destination-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDeliveryDestinationPolicy on a nonexistent delivery destination fails with
    ResourceNotFoundException, while the identical call on an existing destination succeeds.
    """
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    log_group = ctx.unique_name("sim2real-behav-ddpol-lg-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"][0]["arn"]

    dest_name = ctx.unique_name("sim2real-behav-ddpol-dest-")
    logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
    )
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))
    ctx.on_cleanup(lambda: logs.delete_delivery_destination_policy(deliveryDestinationName=dest_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountDelivery",
                "Effect": "Allow",
                "Principal": {"AWS": account},
                "Action": "logs:CreateDelivery",
                "Resource": "*",
            }
        ],
    }
    policy_doc = json.dumps(policy)

    logs.put_delivery_destination_policy(
        deliveryDestinationName=dest_name, deliveryDestinationPolicy=policy_doc
    )
    got = logs.get_delivery_destination_policy(deliveryDestinationName=dest_name)
    assert got["policy"].get("deliveryDestinationPolicy"), (
        f"positive control failed: policy did not attach to a real destination, got {got!r}"
    )

    missing_dest_name = ctx.unique_name("sim2real-behav-nosuchdest-")
    code, msg = _error(
        lambda: logs.put_delivery_destination_policy(
            deliveryDestinationName=missing_dest_name,
            deliveryDestinationPolicy=policy_doc,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for PutDeliveryDestinationPolicy "
        f"against a nonexistent destination, got {code!r}"
    )
    assert msg == "Requested Delivery Destination does not exist in this account.", f"got {msg!r}"


def _error(fn: Callable[[], Any]) -> tuple:
    """Call fn(); return its (error code, error message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
