"""create-rule-unsupported-resource-type-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-rule-unsupported-resource-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNotificationRule rejects an existing Resource of an unsupported type (an SNS topic)
    even with a valid target; a CodeDeploy application resource still succeeds."""
    unsupported_resource_arn = _sns_topic_with_publish_policy(ctx)  # real, but not a supported resource type
    target_arn = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    bad_name = ctx.unique_name("sim2real-behav-rule-unsupported-")
    code, message = _client_error(
        lambda: csn.create_notification_rule(
            Name=bad_name,
            EventTypeIds=_EVENT_TYPE_IDS,
            Resource=unsupported_resource_arn,
            Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
            DetailType="BASIC",
        )
    )
    assert code == "ValidationException", f"expected ValidationException for unsupported resource type, got {code!r}"
    expected_message = (
        "The resource ARN is not valid. The ARN must be a supported AWS CodeStar Notifications "
        "resource type. Valid resource types include AWS CodeBuild, AWS CodeCommit, AWS CodeDeploy "
        "and AWS CodePipeline resources."
    )
    assert message == expected_message, (
        f"unsupported-resource refusal message: expected {expected_message!r}, got {message!r}"
    )

    # Effect absent: no rule exists for that (unsupported) resource.
    listed = csn.list_notification_rules(Filters=[{"Name": "RESOURCE", "Value": unsupported_resource_arn}])
    assert listed["NotificationRules"] == []

    # Positive control: a supported resource type (CodeDeploy application) succeeds.
    good_resource_arn = _codedeploy_resource_arn(ctx)
    good_name = ctx.unique_name("sim2real-behav-rule-supported-")
    good_arn = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=good_name,
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=good_resource_arn,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
        Tags={"sim2real": "true"},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=good_arn))
    assert csn.describe_notification_rule(Arn=good_arn)["Resource"] == good_resource_arn


# ===== helpers =====
def _codedeploy_resource_arn(ctx) -> str:
    cd = ctx.client("codedeploy")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-cdapp-")
    cd.create_application(
        applicationName=name, computePlatform="Server", tags=[{"Key": "sim2real", "Value": "true"}]
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    account = sts.get_caller_identity()["Account"]
    return f"arn:aws:codedeploy:{ctx.region}:{account}:application:{name}"


def _sns_topic_with_publish_policy(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-")
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": "true"}])["TopicArn"]
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
