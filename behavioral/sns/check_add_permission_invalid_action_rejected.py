"""add-permission-invalid-action-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-permission-invalid-action-rejected"
GROUP = 'overly-permissive'
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

def _policy_sids(client, topic_arn) -> set[str]:
    """Statement Sids currently in the topic's access policy (independent read)."""
    policy = json.loads(client.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"])
    return {stmt.get("Sid") for stmt in policy.get("Statement", [])}

def _error(fn):
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission must reject an ActionName that is not a real SNS action, and must not
    insert a policy statement for the rejected attempt — while a real action is still accepted
    on the same topic (positive control)."""
    ev = ctx.client("sns")
    account_id = _account_id(ctx)
    topic_arn = _create_topic(
        ev, ctx, ctx.unique_name("sim2real-behav-sns-badaction-"),
        tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )

    good_label = ctx.unique_name("sim2real-behav-goodaction-")
    ev.add_permission(TopicArn=topic_arn, Label=good_label, AWSAccountId=[account_id], ActionName=["Publish"])
    sids = _policy_sids(ev, topic_arn)
    assert good_label in sids, (
        f"positive control failed: expected label {good_label!r} for a real ActionName in policy {sids}"
    )

    bad_label = ctx.unique_name("sim2real-behav-badaction-")
    code, message = _error(
        lambda: ev.add_permission(
            TopicArn=topic_arn, Label=bad_label, AWSAccountId=[account_id],
            ActionName=['NotARealSnsAction'],
        )
    )
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for a bogus ActionName, got {code}"
    )
    assert message == "Invalid parameter: Policy statement action out of service scope!", (
        f"unexpected InvalidParameter message for a bogus ActionName: {message!r}"
    )

    sids = _policy_sids(ev, topic_arn)
    assert bad_label not in sids, (
        f"rejected AddPermission must not insert a statement: found {bad_label!r} in policy {sids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
