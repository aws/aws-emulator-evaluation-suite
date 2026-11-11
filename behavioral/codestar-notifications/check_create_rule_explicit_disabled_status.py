"""create-rule-explicit-disabled-status."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-rule-explicit-disabled-status"
GROUP = "state"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNotificationRule with Status=DISABLED persists as DISABLED, not the ENABLED default."""
    resource_arn = _codedeploy_resource_arn(ctx)
    target_arn = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    name = ctx.unique_name("sim2real-behav-rule-")
    created = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=name,
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_arn,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
        Status="DISABLED",
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=arn))

    desc = csn.describe_notification_rule(Arn=arn)
    assert desc["Status"] == "DISABLED", (
        f"explicit Status=DISABLED at creation did not persist: describe_notification_rule "
        f"returned Status={desc['Status']!r} (expected 'DISABLED')"
    )


# ===== helpers =====
def _codedeploy_resource_arn(ctx) -> str:
    cd = ctx.client("codedeploy")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-cdapp-")
    cd.create_application(applicationName=name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    account = sts.get_caller_identity()["Account"]
    return f"arn:aws:codedeploy:{ctx.region}:{account}:application:{name}"


def _sns_topic_with_publish_policy(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-")
    arn = sns.create_topic(Name=name)["TopicArn"]
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
