"""describe-rule-malformed-arn-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "describe-rule-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeNotificationRule rejects an Arn off the notificationrule pattern with
    AccessDeniedException (the authorization check runs before any lookup), distinct from
    ResourceNotFoundException; a real Arn still succeeds."""
    resource_arn = _codedeploy_resource_arn(ctx)
    target_arn = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    name = ctx.unique_name("sim2real-behav-rule-")
    real_arn = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=name,
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_arn,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=real_arn))

    # Malformed: wrong fixed segment ("wrongsegment" instead of "notificationrule").
    malformed_arn = real_arn.replace("notificationrule/", "wrongsegment/")
    assert malformed_arn != real_arn, f"replace() did not change the Arn: {real_arn!r}"

    code, message = _client_error(lambda: csn.describe_notification_rule(Arn=malformed_arn))
    assert code == "AccessDeniedException", f"expected AccessDeniedException for malformed Arn, got {code!r}"
    expected_message = (
        "You don't have sufficient permissions to perform operations on the following resource: "
        f"{malformed_arn}. For more information, see the notifications feature documentation in "
        "the user guide for the Developer Tools console."
    )
    assert message == expected_message, (
        f"malformed-Arn refusal message: expected {expected_message!r}, got {message!r}"
    )

    # Positive control: the real, well-formed Arn still describes successfully.
    desc = csn.describe_notification_rule(Arn=real_arn)
    assert desc["Name"] == name, f"expected Name {name!r} on the well-formed Arn, got {desc['Name']!r}"


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
