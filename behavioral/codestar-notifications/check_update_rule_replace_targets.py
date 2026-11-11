"""update-rule-replace-targets."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-rule-replace-targets"
GROUP = "state"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNotificationRule Targets replaces the whole target list, not appends to it."""
    resource_arn = _codedeploy_resource_arn(ctx)
    old_target = _sns_topic_with_publish_policy(ctx)
    new_target = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = csn.create_notification_rule(
        Name=name,
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_arn,
        Targets=[{"TargetType": "SNS", "TargetAddress": old_target}],
        DetailType="BASIC",
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=arn))

    before = csn.describe_notification_rule(Arn=arn)
    before_addresses = [t["TargetAddress"] for t in before["Targets"]]
    assert before_addresses == [old_target], f"expected [{old_target}], got {before_addresses}"

    csn.update_notification_rule(Arn=arn, Targets=[{"TargetType": "SNS", "TargetAddress": new_target}])

    after = csn.describe_notification_rule(Arn=arn)
    addresses = [t["TargetAddress"] for t in after["Targets"]]
    assert addresses == [new_target], f"expected update to replace targets with [{new_target}], got {addresses}"
    assert old_target not in addresses, f"old target {old_target} still present after replace: {addresses}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
