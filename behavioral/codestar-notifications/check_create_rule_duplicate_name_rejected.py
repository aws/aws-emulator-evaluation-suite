"""create-rule-duplicate-name-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-rule-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNotificationRule rejects a Name already used by an existing rule in the account,
    even when pointed at a different resource, while a distinct new name still succeeds."""
    resource_a = _codedeploy_resource_arn(ctx)
    resource_b = _codedeploy_resource_arn(ctx)
    target_arn = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    shared_name = ctx.unique_name("sim2real-behav-dup-")
    first_arn = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=shared_name,
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_a,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
        Tags={"sim2real": "behav-dup"},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=first_arn))

    code, message = _client_error(
        lambda: csn.create_notification_rule(
            Name=shared_name,
            EventTypeIds=_EVENT_TYPE_IDS,
            Resource=resource_b,
            Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
            DetailType="BASIC",
        )
    )
    assert code == "ResourceAlreadyExistsException", (
        f"a second CreateNotificationRule reusing name {shared_name!r} on a different resource "
        f"was expected to fail with ResourceAlreadyExistsException, got {code!r}"
    )
    expected_message = (
        "The notification rule was not created because another notification rule already exists "
        "with the same name. Notification rule names must be unique within an AWS account. This "
        "helps prevent exceeding the maximum allowed number of notification rules."
    )
    assert message == expected_message, (
        f"duplicate-name refusal message: expected {expected_message!r}, got {message!r}"
    )

    # Effect absent: resource_b has no rule at all -- the duplicate attempt did not create one.
    listed_b = csn.list_notification_rules(Filters=[{"Name": "RESOURCE", "Value": resource_b}])
    assert listed_b["NotificationRules"] == [], (
        f"resource_b {resource_b!r} should have no notification rule after the rejected "
        f"duplicate create, found {listed_b['NotificationRules']!r}"
    )
    # The original rule is still exactly as it was.
    first_resource_after = csn.describe_notification_rule(Arn=first_arn)["Resource"]
    assert first_resource_after == resource_a, (
        f"the original rule {first_arn!r} should still point at {resource_a!r} after the "
        f"rejected duplicate create, found {first_resource_after!r}"
    )

    # Positive control: a distinct name on resource_b succeeds.
    other_name = ctx.unique_name("sim2real-behav-dup-other-")
    other_arn = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=other_name,
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_b,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
        Tags={"sim2real": "behav-dup"},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=other_arn))
    other_name_after = csn.describe_notification_rule(Arn=other_arn)["Name"]
    assert other_name_after == other_name, (
        f"the distinct-name rule on resource_b should be named {other_name!r}, found "
        f"{other_name_after!r}"
    )


# ===== helpers =====
def _codedeploy_resource_arn(ctx) -> str:
    cd = ctx.client("codedeploy")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-cdapp-")
    cd.create_application(
        applicationName=name,
        computePlatform="Server",
        tags=[{"Key": "sim2real", "Value": "behav-dup"}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    account = sts.get_caller_identity()["Account"]
    return f"arn:aws:codedeploy:{ctx.region}:{account}:application:{name}"


def _sns_topic_with_publish_policy(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-")
    arn = sns.create_topic(
        Name=name, Tags=[{"Key": "sim2real", "Value": "behav-dup"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCodeStarNotifications_publish",
                "Effect": "Allow",
                "Principal": {"Service": "codestar-notifications.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": arn,
            }
        ],
    }
    sns.set_topic_attributes(TopicArn=arn, AttributeName="Policy", AttributeValue=json.dumps(policy))
    return arn


def _client_error(fn):
    """Call fn(); return the (code, message) of the botocore error it raises. An unexpected
    SUCCESS raises, so an accepted call is reported as such rather than as an error-code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_notification_rule_with_retry(ctx, csn, **kwargs):
    """Retry CreateNotificationRule on the ConfigurationException AWS returns while the account's
    CodeStar Notifications service-linked role is being created, to a deadline; any other error
    raises at once."""
    import time

    from botocore.exceptions import ClientError

    left = ctx.time_left()
    deadline = time.monotonic() + (150.0 if left is None else min(150.0, left))
    while True:
        try:
            return csn.create_notification_rule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code != "ConfigurationException" or "service-linked role" not in msg:
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
