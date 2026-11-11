"""update-rule-replace-event-types."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-rule-replace-event-types"
GROUP = "state"
SERVICES = ["codestar-notifications"]

_INITIAL_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]
_REPLACEMENT_EVENT_TYPE_IDS = ["codedeploy-application-deployment-failed"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNotificationRule replaces EventTypeIds wholesale -- old event type disappears."""
    resource_arn = _codedeploy_resource_arn(ctx)
    target_arn = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=name,
        EventTypeIds=_INITIAL_EVENT_TYPE_IDS,
        Resource=resource_arn,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
        Tags={"sim2real": CHECK},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=arn))

    before = csn.describe_notification_rule(Arn=arn)
    before_ids = {e["EventTypeId"] for e in before["EventTypes"]}
    assert before_ids == set(_INITIAL_EVENT_TYPE_IDS), (
        f"expected initial EventTypeIds {set(_INITIAL_EVENT_TYPE_IDS)}, got {before_ids}"
    )

    csn.update_notification_rule(Arn=arn, EventTypeIds=_REPLACEMENT_EVENT_TYPE_IDS)

    after = csn.describe_notification_rule(Arn=arn)
    after_ids = {e["EventTypeId"] for e in after["EventTypes"]}
    assert after_ids == set(_REPLACEMENT_EVENT_TYPE_IDS), (
        f"expected UpdateNotificationRule to REPLACE EventTypeIds with "
        f"{set(_REPLACEMENT_EVENT_TYPE_IDS)}, got {after_ids}"
    )
    assert _INITIAL_EVENT_TYPE_IDS[0] not in after_ids, (
        f"expected the pre-update event type {_INITIAL_EVENT_TYPE_IDS[0]!r} to be gone after "
        f"replace, but it is still present in {after_ids}"
    )


# ===== helpers =====
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


def _codedeploy_resource_arn(ctx) -> str:
    cd = ctx.client("codedeploy")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-cdapp-")
    cd.create_application(
        applicationName=name,
        computePlatform="Server",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    account = sts.get_caller_identity()["Account"]
    return f"arn:aws:codedeploy:{ctx.region}:{account}:application:{name}"


def _sns_topic_with_publish_policy(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-")
    arn = sns.create_topic(
        Name=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
