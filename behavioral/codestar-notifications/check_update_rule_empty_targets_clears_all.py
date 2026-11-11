"""update-rule-empty-targets-clears-all."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-rule-empty-targets-clears-all"
GROUP = "state"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNotificationRule accepts an empty Targets list (min length 0) and clears all targets."""
    resource_arn = _codedeploy_resource_arn(ctx)
    target_arn = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = csn.create_notification_rule(
        Name=name,
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_arn,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
        Tags={"sim2real": "true"},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=arn))
    before = csn.describe_notification_rule(Arn=arn)["Targets"]
    assert len(before) == 1, f"expected 1 target before clearing, got {before!r}"

    csn.update_notification_rule(Arn=arn, Targets=[])

    desc = csn.describe_notification_rule(Arn=arn)
    assert desc["Targets"] == [], f"expected Targets cleared to [], got {desc['Targets']!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
