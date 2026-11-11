"""add-permission-nonexistent-topic-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-permission-nonexistent-topic-fails"
GROUP = 'permissions'
SERVICES = ['sns']


def _reject_or_raise(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) of its ClientError.

    An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _policy_sids(sns, arn):
    """Statement ids present in the topic's access policy."""
    policy = json.loads(sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"])
    return {stmt.get("Sid") for stmt in policy.get("Statement", [])}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission on a deleted topic fails NotFound, while the identical call succeeds on the
    live topic and again once it is recreated under the same name (and so the same ARN)."""
    sns = ctx.client("sns")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-sns-topic-")
    label = "sim2real-probe-permission"

    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    def _add_permission(target_arn):
        sns.add_permission(
            TopicArn=target_arn, Label=label,
            AWSAccountId=[account_id], ActionName=["Publish"],
        )

    try:
        _add_permission(arn)
        control_error = None
    except ClientError as exc:
        control_error = exc.response.get("Error", {}).get("Code")
    assert control_error is None, (
        f"positive control failed: AddPermission on a live topic should succeed, got {control_error!r}"
    )
    assert label in _policy_sids(sns, arn), (
        f"expected {label!r} in the live topic's policy statements after AddPermission"
    )

    sns.delete_topic(TopicArn=arn)
    gone_code, gone_message = _reject_or_raise(lambda: sns.get_topic_attributes(TopicArn=arn))
    assert gone_code == "NotFound", f"expected NotFound reading a deleted topic, got {gone_code!r}"
    assert gone_message == "Topic does not exist", (
        f"unexpected NotFound message reading a deleted topic: {gone_message!r}"
    )

    reject_code, reject_message = _reject_or_raise(lambda: _add_permission(arn))
    assert reject_code == "NotFound", f"expected NotFound, got {reject_code!r}"
    assert reject_message == "Topic does not exist", (
        f"unexpected NotFound message for AddPermission on a deleted topic: {reject_message!r}"
    )

    # SNS topic ARNs are deterministic on account+region+name, so recreating reuses the ARN.
    new_arn = sns.create_topic(Name=name)["TopicArn"]
    assert new_arn == arn, f"expected the recreated topic to reuse the ARN, got {new_arn!r} vs {arn!r}"

    try:
        _add_permission(new_arn)
        restore_error = None
    except ClientError as exc:
        restore_error = exc.response.get("Error", {}).get("Code")
    assert restore_error is None, (
        f"expected AddPermission to succeed again once the topic was recreated, got {restore_error!r}"
    )
    assert label in _policy_sids(sns, new_arn), (
        f"expected {label!r} in the recreated topic's policy statements after AddPermission"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
