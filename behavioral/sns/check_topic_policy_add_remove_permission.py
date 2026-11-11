"""topic-policy-add-remove-permission."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "topic-policy-add-remove-permission"
GROUP = 'policy-and-tags'
SERVICES = ['sns']

def _create_topic(client, ctx, name, attributes=None, tags=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if tags:
        kwargs["Tags"] = tags
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

def _account_id(ctx) -> str:
    """Caller account id (STS, with an SNS-topic-ARN fallback for targets without STS)."""
    try:
        return ctx.client("sts").get_caller_identity()["Account"]
    except Exception:
        sns = ctx.client("sns")
        probe = sns.create_topic(Name=f"sim2real-behav-acctprobe-{uuid.uuid4().hex[:8]}")["TopicArn"]
        try:
            return probe.split(":")[4]
        finally:
            try:
                sns.delete_topic(TopicArn=probe)
            except Exception:
                pass

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddPermission inserts a statement (by Label) into the topic policy; RemovePermission deletes it."""
    ev = ctx.client("sns")
    topic_arn = _create_topic(
        ev, ctx, ctx.unique_name("sim2real-behav-sns-perm-"),
        tags=[{"Key": "env", "Value": "fidelity"}],
    )
    label = "fidelity-check-statement"
    ev.add_permission(
        TopicArn=topic_arn,
        Label=label,
        AWSAccountId=[_account_id(ctx)],
        ActionName=["Publish"],
    )
    policy = json.loads(ev.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"])
    sids = {stmt.get("Sid") for stmt in policy.get("Statement", [])}
    assert label in sids, f"expected statement labeled {label!r} in topic policy, got {sids}"
    ev.remove_permission(TopicArn=topic_arn, Label=label)
    policy_after = json.loads(ev.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"])
    sids_after = {stmt.get("Sid") for stmt in policy_after.get("Statement", [])}
    assert label not in sids_after, f"expected statement {label!r} removed from policy, still present: {sids_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
