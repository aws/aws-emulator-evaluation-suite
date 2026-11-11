"""add-remove-permission-updates-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "add-remove-permission-updates-policy"
GROUP = "state"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddPermission adds a labeled Statement to the queue policy; RemovePermission removes it by Label."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.add_permission(
        QueueUrl=url, Label="AllowSend", AWSAccountIds=[account_id], Actions=["SendMessage"]
    )
    policy = json.loads(sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"])
    labels = {stmt.get("Sid") for stmt in policy["Statement"]}
    assert "AllowSend" in labels, f"expected Sid 'AllowSend' in policy statements after AddPermission, got {labels}"

    sqs.remove_permission(QueueUrl=url, Label="AllowSend")
    attrs_after = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {})
    policy_after = attrs_after.get("Policy")
    if policy_after:
        labels_after = {stmt.get("Sid") for stmt in json.loads(policy_after)["Statement"]}
        assert "AllowSend" not in labels_after, (
            f"expected Sid 'AllowSend' removed from policy statements after RemovePermission, got {labels_after}"
        )
    # else: the Policy attribute is absent entirely because the removed statement was the only one -- also correct.


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
