"""remove-permission-nonexistent-topic-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-permission-nonexistent-topic-fails"
GROUP = "permissions"
SERVICES = ["sns"]


def _error(fn):
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _statement_sids(sns, arn):
    """The set of Sid values present in the topic's access policy, read independently."""
    policy = json.loads(sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"])
    return {stmt.get("Sid") for stmt in policy.get("Statement", [])}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemovePermission on a deleted topic fails NotFound, while the identical call still works
    on a live topic before the delete and again once the topic is recreated under the same name.
    """
    sns = ctx.client("sns")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-sns-rmperm-")
    label = "sim2real-probe-removable"

    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    # Positive control: grant the statement, then remove it from the live topic, proven by an
    # independent read of the policy rather than the mutating call's own response.
    sns.add_permission(TopicArn=arn, Label=label, AWSAccountId=[account_id], ActionName=["Publish"])
    assert label in _statement_sids(sns, arn), (
        f"expected {label!r} present after AddPermission on the live topic"
    )
    sns.remove_permission(TopicArn=arn, Label=label)
    assert label not in _statement_sids(sns, arn), (
        f"expected {label!r} gone after RemovePermission on the live topic"
    )

    # Break exactly one thing: the topic itself is gone.
    sns.delete_topic(TopicArn=arn)
    gone_code, gone_message = _error(lambda: sns.get_topic_attributes(TopicArn=arn))
    assert gone_code == "NotFound", f"expected NotFound reading a deleted topic, got {gone_code!r}"
    assert gone_message == "Topic does not exist", (
        f"unexpected NotFound message reading a deleted topic: {gone_message!r}"
    )

    reject_code, reject_message = _error(lambda: sns.remove_permission(TopicArn=arn, Label=label))
    assert reject_code == "NotFound", (
        f"expected NotFound for RemovePermission on a deleted topic, got {reject_code!r}"
    )
    assert reject_message == "Topic does not exist", (
        f"unexpected message for RemovePermission on a deleted topic: {reject_message!r}"
    )

    # Restore: SNS topic ARNs are deterministic on account+region+name, so recreating reuses it.
    new_arn = sns.create_topic(Name=name)["TopicArn"]
    assert new_arn == arn, f"expected the recreated topic to reuse the ARN, got {new_arn!r} vs {arn!r}"

    sns.add_permission(TopicArn=new_arn, Label=label, AWSAccountId=[account_id], ActionName=["Publish"])
    assert label in _statement_sids(sns, new_arn), (
        f"expected {label!r} present after AddPermission on the recreated topic"
    )
    sns.remove_permission(TopicArn=new_arn, Label=label)
    assert label not in _statement_sids(sns, new_arn), (
        f"expected RemovePermission to succeed again on the recreated topic, "
        f"but {label!r} is still present"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
