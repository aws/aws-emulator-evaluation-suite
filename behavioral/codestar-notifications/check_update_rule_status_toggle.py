"""update-rule-status-toggle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-rule-status-toggle"
GROUP = "state"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNotificationRule can flip Status from ENABLED to DISABLED without deleting the rule."""
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
        Status="ENABLED",
        Tags={"sim2real:managed": "true"},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=arn))
    initial_status = csn.describe_notification_rule(Arn=arn)["Status"]
    assert initial_status == "ENABLED", f"expected ENABLED right after create, got {initial_status!r}"

    csn.update_notification_rule(Arn=arn, Status="DISABLED")

    desc = csn.describe_notification_rule(Arn=arn)
    assert desc["Status"] == "DISABLED", f"expected DISABLED after update, got {desc['Status']!r}"
    # The rule itself must still exist (not deleted) and keep its other configuration.
    assert desc["Name"] == name, f"expected rule Name to survive the toggle, got {desc['Name']!r} vs {name!r}"
    assert len(desc["Targets"]) == 1, f"expected 1 target to survive the toggle, got {len(desc['Targets'])}"


def _codedeploy_resource_arn(ctx) -> str:
    cd = ctx.client("codedeploy")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-cdapp-")
    cd.create_application(
        applicationName=name,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    account = sts.get_caller_identity()["Account"]
    return f"arn:aws:codedeploy:{ctx.region}:{account}:application:{name}"


def _sns_topic_with_publish_policy(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-")
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real:managed", "Value": "true"}])["TopicArn"]
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
