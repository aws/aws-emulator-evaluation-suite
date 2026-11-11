"""create-rule-nonexistent-event-type-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-rule-nonexistent-event-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]
_BOGUS_EVENT_TYPE_ID = "sim2real-behav-nonexistent-event-type-id"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNotificationRule validates EventTypeIds against its catalog: an unknown event type
    ID is rejected with ValidationException, while a known one on the same resource succeeds."""
    resource_arn = _codedeploy_resource_arn(ctx)
    target_arn = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    bad_name = ctx.unique_name("sim2real-behav-rule-bad-")
    err = _error(
        lambda: csn.create_notification_rule(
            Name=bad_name,
            EventTypeIds=[_BOGUS_EVENT_TYPE_ID],
            Resource=resource_arn,
            Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
            DetailType="BASIC",
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException for nonexistent EventTypeId, got {err!r}"
    expected = (
        "The notification rule cannot be created or modified because the following notification "
        f"event type ID is not valid: {_BOGUS_EVENT_TYPE_ID}. For more information, see the AWS "
        "CodeStar Notifications API Reference."
    )
    assert err.get("Message") == expected, (err.get("Message"), expected)

    # Effect absent: no rule with that name exists anywhere in the account.
    listed = csn.list_notification_rules(Filters=[{"Name": "RESOURCE", "Value": resource_arn}])
    assert listed["NotificationRules"] == [], f"expected no rule named {bad_name!r}, found {listed['NotificationRules']!r}"

    # Positive control: the same resource/target with a real, known event type ID succeeds.
    good_name = ctx.unique_name("sim2real-behav-rule-good-")
    good_arn = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=good_name,
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_arn,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
        Tags={"sim2real": "behavioral"},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=good_arn))
    described_name = csn.describe_notification_rule(Arn=good_arn)["Name"]
    assert described_name == good_name, f"expected rule name {good_name!r}, DescribeNotificationRule returned {described_name!r}"


# ===== helpers =====
def _codedeploy_resource_arn(ctx) -> str:
    cd = ctx.client("codedeploy")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-cdapp-")
    cd.create_application(applicationName=name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    account = sts.get_caller_identity()["Account"]
    arn = f"arn:aws:codedeploy:{ctx.region}:{account}:application:{name}"
    cd.tag_resource(ResourceArn=arn, Tags=[{"Key": "sim2real", "Value": "behavioral"}])
    return arn


def _sns_topic_with_publish_policy(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-")
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": "behavioral"}])["TopicArn"]
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


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises, so an accepted
    call is reported as such rather than as an error-code mismatch (and the accepted resource
    would otherwise leak, untracked by any ctx.on_cleanup)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_notification_rule_with_retry(ctx, csn, **kwargs):
    """Retry CreateNotificationRule on the ConfigurationException AWS returns while the account's
    CodeStar Notifications service-linked role is being created, to a deadline; any other error
    raises at once."""
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



