"""target-status-reaches-active-with-valid-policy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "target-status-reaches-active-with-valid-policy"
GROUP = "state"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Targets on one rule reach ACTIVE whether or not their SNS topic grants a publish policy:
    TargetStatus is not gated on the topic's resource policy at creation time."""
    resource_arn = _codedeploy_resource_arn(ctx)
    policied_target = _sns_topic_with_publish_policy(ctx)
    unpolicied_target = _sns_topic_without_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=name,
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_arn,
        Targets=[
            {"TargetType": "SNS", "TargetAddress": policied_target},
            {"TargetType": "SNS", "TargetAddress": unpolicied_target},
        ],
        DetailType="BASIC",
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=arn))

    policied_status, unpolicied_status = _poll_until_targets_settle(
        csn, arn, policied_target, unpolicied_target, timeout_s=90.0
    )
    assert policied_status == "ACTIVE", (
        f"target backed by a correctly-policied topic never reached ACTIVE, last seen status: {policied_status!r}"
    )
    assert unpolicied_status == "ACTIVE", (
        "target backed by a topic with NO publish policy did not reach ACTIVE alongside the "
        f"correctly-policied target -- real AWS is known to mark it ACTIVE too, got {unpolicied_status!r}"
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


def _sns_topic_without_publish_policy(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-nopolicy-")
    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _poll_until_targets_settle(
    csn, rule_arn: str, policied_target_arn: str, unpolicied_target_arn: str, timeout_s: float
) -> tuple[str | None, str | None]:
    """Polls both targets on the same rule at the same instants, so each status is always read
    at the exact moment the other's is -- rather than guessing how long AWS takes to settle
    either one."""
    deadline = time.monotonic() + timeout_s
    policied_status = None
    unpolicied_status = None
    while time.monotonic() < deadline:
        desc = csn.describe_notification_rule(Arn=rule_arn)
        for target in desc["Targets"]:
            if target["TargetAddress"] == policied_target_arn:
                policied_status = target["TargetStatus"]
            elif target["TargetAddress"] == unpolicied_target_arn:
                unpolicied_status = target["TargetStatus"]
        if policied_status == "ACTIVE" and unpolicied_status == "ACTIVE":
            return policied_status, unpolicied_status
        time.sleep(3)
    return policied_status, unpolicied_status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
