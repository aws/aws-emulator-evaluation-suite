"""delete-target-force-unsubscribe-all-removes-across-rules."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-target-force-unsubscribe-all-removes-across-rules"
GROUP = "state"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTarget(ForceUnsubscribeAll=True) removes the target from every rule in the account."""
    resource_a = _codedeploy_resource_arn(ctx)
    resource_b = _codedeploy_resource_arn(ctx)
    shared_target = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    rule_a = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=ctx.unique_name("sim2real-behav-rule-a-"),
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_a,
        Targets=[{"TargetType": "SNS", "TargetAddress": shared_target}],
        DetailType="BASIC",
        Tags={"sim2real:managed": "true"},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=rule_a))

    rule_b = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=ctx.unique_name("sim2real-behav-rule-b-"),
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_b,
        Targets=[{"TargetType": "SNS", "TargetAddress": shared_target}],
        DetailType="BASIC",
        Tags={"sim2real:managed": "true"},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=rule_b))

    targets_a = csn.describe_notification_rule(Arn=rule_a)["Targets"]
    targets_b = csn.describe_notification_rule(Arn=rule_b)["Targets"]
    assert len(targets_a) == 1, f"expected 1 target on rule_a before delete, got {targets_a!r}"
    assert len(targets_b) == 1, f"expected 1 target on rule_b before delete, got {targets_b!r}"

    csn.delete_target(TargetAddress=shared_target, ForceUnsubscribeAll=True)

    desc_a = csn.describe_notification_rule(Arn=rule_a)["Targets"]
    desc_b = csn.describe_notification_rule(Arn=rule_b)["Targets"]
    assert desc_a == [], f"expected rule_a to have no targets after ForceUnsubscribeAll, got {desc_a!r}"
    assert desc_b == [], f"expected rule_b to have no targets after ForceUnsubscribeAll, got {desc_b!r}"


# ===== helpers =====
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
