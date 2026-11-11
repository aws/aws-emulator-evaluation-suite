"""list-notification-rules-filter-by-resource."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-notification-rules-filter-by-resource"
GROUP = "listing"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNotificationRules filtered by RESOURCE returns exactly the rule for that resource ARN,
    and stops once that rule is deleted."""
    resource_arn = _codedeploy_resource_arn(ctx)
    other_resource_arn = _codedeploy_resource_arn(ctx)
    target_arn = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    arn = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=ctx.unique_name("sim2real-behav-rule-"),
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_arn,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
        Tags={"sim2real:managed": "true"},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=arn))

    other_arn = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=ctx.unique_name("sim2real-behav-rule-"),
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=other_resource_arn,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
        Tags={"sim2real:managed": "true"},
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=other_arn))

    resp = csn.list_notification_rules(Filters=[{"Name": "RESOURCE", "Value": resource_arn}])
    arns = {r["Arn"] for r in resp["NotificationRules"]}
    assert arns == {arn}, f"expected RESOURCE filter to return exactly {{{arn!r}}}, got {arns}"
    assert other_arn not in arns, f"other rule {other_arn} leaked into RESOURCE filter result {arns}"

    # Cleanup already deletes other_arn at teardown; prove the delete here instead so the
    # RESOURCE filter is shown tracking removal, not just creation. The pre-delete read is the
    # positive control on this exact wiring — without it, a target where the filter never
    # matched other_resource_arn at all would pass the post-delete check for free.
    resp_before_delete = csn.list_notification_rules(Filters=[{"Name": "RESOURCE", "Value": other_resource_arn}])
    before = {r["Arn"] for r in resp_before_delete["NotificationRules"]}
    assert before == {other_arn}, f"expected RESOURCE filter on other_resource_arn to return {{{other_arn!r}}}, got {before}"

    csn.delete_notification_rule(Arn=other_arn)
    resp_after_delete = csn.list_notification_rules(Filters=[{"Name": "RESOURCE", "Value": other_resource_arn}])
    remaining = {r["Arn"] for r in resp_after_delete["NotificationRules"]}
    assert other_arn not in remaining, f"deleted rule {other_arn} still present in RESOURCE filter result {remaining}"

    code, message = _client_error(lambda: csn.describe_notification_rule(Arn=other_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException describing deleted rule, got {code}"
    other_id = other_arn.rsplit("/", 1)[1]
    expected_message = (
        f"A notification rule with the following ID cannot be found: {other_id}. Verify that the "
        "notification rule ID is correct, and then try again."
    )
    assert message == expected_message, (
        f"describe not-found message: expected {expected_message!r}, got {message!r}"
    )

    code, message = _client_error(lambda: csn.tag_resource(Arn=other_arn, Tags={"late": "tag"}))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException tagging deleted rule, got {code}"
    expected_message = (
        f"The following resource ARN was not found: {other_arn}. Make sure that the resource ARN "
        "is correct and then try again."
    )
    assert message == expected_message, (
        f"tag not-found message: expected {expected_message!r}, got {message!r}"
    )


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


def _client_error(fn):
    """Call fn(); return the (code, message) of the botocore error it raises. An unexpected
    SUCCESS raises, so an accepted call is reported as such rather than as an error-code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
