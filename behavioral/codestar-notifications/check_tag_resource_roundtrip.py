"""tag-resource-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "tag-resource-roundtrip"
GROUP = "tagging"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags that are then visible via both ListTagsForResource and Describe."""
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
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=arn))
    initial_tags = csn.list_tags_for_resource(Arn=arn)["Tags"]
    assert initial_tags == {}, f"expected freshly-created rule to have no tags, got {initial_tags!r}"

    result = csn.tag_resource(Arn=arn, Tags={"env": "sim2real-test"})
    assert result["Tags"] == {"env": "sim2real-test"}, f"TagResource response tags mismatch: {result['Tags']!r}"

    listed_tags = csn.list_tags_for_resource(Arn=arn)["Tags"]
    assert listed_tags == {"env": "sim2real-test"}, f"ListTagsForResource did not reflect the tag: {listed_tags!r}"
    described_tags = csn.describe_notification_rule(Arn=arn)["Tags"]
    assert described_tags == {"env": "sim2real-test"}, f"DescribeNotificationRule did not reflect the tag: {described_tags!r}"


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
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
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
