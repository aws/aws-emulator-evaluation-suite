"""remove-permission-unknown-label-is-idempotent."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "remove-permission-unknown-label-is-idempotent"
GROUP = 'permissions'
SERVICES = ['sns']


def _create_topic(ctx, name=None):
    """Create a tagged topic, register its teardown, and return its ARN."""
    sns = ctx.client("sns")
    name = name or ctx.unique_name("sim2real-behav-sns-topic-")
    tags_kv = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]
    arn = sns.create_topic(Name=name, Tags=tags_kv)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _statement_sids(sns, arn):
    """Read the topic's policy statements (Sid set) via an independent GetTopicAttributes read."""
    policy = json.loads(sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"])
    return {stmt.get("Sid") for stmt in policy.get("Statement", [])}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemovePermission for a label that was never added is a no-op success in real SNS, and
    leaves an existing, unrelated permission statement untouched."""
    sns = ctx.client("sns")
    arn = _create_topic(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    canary_label = ctx.unique_name("sim2real-behav-sns-canary-")

    # Positive control: a real permission exists, proven present via an independent read.
    sns.add_permission(
        TopicArn=arn, Label=canary_label, AWSAccountId=[account_id], ActionName=["Publish"]
    )
    sids_before = _statement_sids(sns, arn)
    assert canary_label in sids_before, (
        f"expected canary label {canary_label!r} in topic policy before the no-op, got {sids_before!r}"
    )

    # RemovePermission for an unknown label succeeds silently; a refusal raises here.
    sns.remove_permission(TopicArn=arn, Label="never-added-label-xyz")

    # Terminal read: an independent GetTopicAttributes call, distinct from RemovePermission,
    # proving the no-op left the unrelated statement's presence exactly unchanged.
    sids_after = _statement_sids(sns, arn)
    assert sids_after == sids_before, (
        f"RemovePermission on an unknown label must not disturb existing statements: "
        f"before={sids_before!r} after={sids_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
