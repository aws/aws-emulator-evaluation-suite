"""get-delivery-destination-policy-returns-empty-when-unset."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-delivery-destination-policy-returns-empty-when-unset"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDeliveryDestinationPolicy on a destination with no policy attached succeeds and returns
    an empty/absent policy (not an error); after PutDeliveryDestinationPolicy it round-trips the
    exact document back."""
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-ddpolicy-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"]

    dest_name = ctx.unique_name("sim2real-ddest-")
    logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": group_arn},
        tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))

    # No policy has ever been attached: expect an empty/absent policy, not an error.
    resp = logs.get_delivery_destination_policy(deliveryDestinationName=dest_name)
    policy = resp.get("policy") or {}
    assert not policy.get("deliveryDestinationPolicy"), (
        f"expected empty policy on a destination with none attached, got: {policy!r}"
    )

    # Now attach a real policy and confirm the mechanism round-trips it exactly. Per AWS's
    # documented cross-account delivery-destination-policy shape, the policy grants a specific
    # AWS account principal permission to logs:CreateDelivery against this destination's ARN
    # (not a service principal / PutLogEvents -- that shape is rejected as invalid).
    dest_arn = logs.get_delivery_destination(name=dest_name)["deliveryDestination"]["arn"]
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realAllowCreateDelivery",
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": ["logs:CreateDelivery"],
                    "Resource": dest_arn,
                },
            ],
        }
    )
    logs.put_delivery_destination_policy(
        deliveryDestinationName=dest_name, deliveryDestinationPolicy=policy_doc
    )
    resp2 = logs.get_delivery_destination_policy(deliveryDestinationName=dest_name)
    stored = json.loads(resp2["policy"]["deliveryDestinationPolicy"])

    # Compare semantically rather than structurally-exact: AWS may normalize a single-element
    # Action list to a bare string (or similar minor JSON-shape normalizations) when it stores
    # the policy, so assert on the meaningful fields instead of raw dict equality.
    assert stored["Version"] == "2012-10-17"
    assert len(stored["Statement"]) == 1
    stmt = stored["Statement"][0]
    stmt_action = stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]]
    assert stmt["Effect"] == "Allow"
    assert account_id in json.dumps(stmt["Principal"])
    assert stmt_action == ["logs:CreateDelivery"]
    assert stmt["Resource"] == dest_arn




if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
