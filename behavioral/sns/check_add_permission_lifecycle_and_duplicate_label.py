"""add-permission-lifecycle-and-duplicate-label."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-permission-lifecycle-and-duplicate-label"
GROUP = 'permissions'
SERVICES = ['sns']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddPermission inserts a policy statement by Label; a reused Label is rejected; RemovePermission deletes it."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-perm-")
    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    label = ctx.unique_name("sim2real-behav-label-")

    sns.add_permission(
        TopicArn=arn, Label=label, AWSAccountId=[account_id], ActionName=["Publish"]
    )
    policy = json.loads(sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"])
    statements = {s.get("Sid"): s for s in policy.get("Statement", [])}
    assert label in statements, f"expected label {label!r} in policy statements {set(statements)}"
    original_action = statements[label].get("Action")

    code, message = _error(
        lambda: sns.add_permission(
            TopicArn=arn, Label=label, AWSAccountId=[account_id], ActionName=["Subscribe"]
        )
    )
    assert code == "InvalidParameter", f"expected InvalidParameter for duplicate label, got {code}"
    assert message == "Invalid parameter: Statement already exists", (
        f"unexpected InvalidParameter message for a duplicate label: {message!r}"
    )

    policy = json.loads(sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"])
    statements = {s.get("Sid"): s for s in policy.get("Statement", [])}
    rejected_action = statements.get(label, {}).get("Action")
    assert rejected_action == original_action, (
        f"rejected duplicate-label AddPermission must leave the existing statement unchanged, "
        f"expected Action {original_action!r}, got {rejected_action!r}"
    )

    sns.remove_permission(TopicArn=arn, Label=label)
    policy = json.loads(sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"])
    sids = {s.get("Sid") for s in policy.get("Statement", [])}
    assert label not in sids, f"label {label!r} should be removed, still present in {sids}"

    sns.add_permission(
        TopicArn=arn, Label=label, AWSAccountId=[account_id], ActionName=["Subscribe"]
    )
    policy = json.loads(sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"])
    sids = {s.get("Sid") for s in policy.get("Statement", [])}
    assert label in sids, f"expected freed label {label!r} to be reusable once removed, got {sids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
