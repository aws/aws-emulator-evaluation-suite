"""list-targets-filter-by-target-address."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-targets-filter-by-target-address"
GROUP = "listing"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTargets filtered by TARGET_ADDRESS returns exactly the matching target, excluding others."""
    resource_arn = _codedeploy_resource_arn(ctx)
    target_arn = _sns_topic_with_publish_policy(ctx)
    other_target_arn = _sns_topic_with_publish_policy(ctx)

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

    csn.subscribe(Arn=arn, Target={"TargetType": "SNS", "TargetAddress": other_target_arn})

    resp = csn.list_targets(Filters=[{"Name": "TARGET_ADDRESS", "Value": target_arn}])
    targets = resp["Targets"]
    addresses = {t["TargetAddress"] for t in targets}
    assert addresses == {target_arn}, f"expected only {target_arn!r}, got {addresses!r}"
    assert other_target_arn not in addresses, (
        f"filter leaked unrelated target {other_target_arn!r} into result {addresses!r}"
    )
    assert targets[0]["TargetType"] == "SNS", f"expected SNS, got {targets[0]['TargetType']!r}"


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
