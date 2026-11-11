"""tag-resource-reserved-prefix-key-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "tag-resource-reserved-prefix-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-notifications"]

_EVENT_TYPE_IDS = ["codedeploy-application-deployment-succeeded"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag key that starts with the reserved 'aws' prefix with
    ValidationException, leaving the rule untagged; a normal key on the same rule
    still succeeds (positive control)."""
    resource_arn = _codedeploy_resource_arn(ctx)
    target_arn = _sns_topic_with_publish_policy(ctx)

    csn = ctx.client("codestar-notifications")
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = _create_notification_rule_with_retry(
        ctx,
        csn,
        Name=name,
        EventTypeIds=_EVENT_TYPE_IDS,
        Resource=resource_arn,
        Targets=[{"TargetType": "SNS", "TargetAddress": target_arn}],
        DetailType="BASIC",
    )["Arn"]
    ctx.on_cleanup(lambda: csn.delete_notification_rule(Arn=arn))
    baseline_tags = csn.list_tags_for_resource(Arn=arn)["Tags"]
    assert baseline_tags == {}, f"expected a freshly created rule to be untagged, got {baseline_tags!r}"

    code, message = _client_error(lambda: csn.tag_resource(Arn=arn, Tags={"aws:reserved": "nope"}))
    assert code == "ValidationException", f"expected ValidationException for reserved 'aws:' tag key prefix, got {code!r}"
    expected_message = (
        "One or more of the following tag keys is reserved: [aws:reserved]. Tag keys cannot begin "
        'with the characters "aws:". For more information, see the AWS CodeStar Notifications API '
        "Reference."
    )
    assert message == expected_message, (
        f"reserved-tag-key refusal message: expected {expected_message!r}, got {message!r}"
    )

    # Effect absent: the rule remains untagged.
    after_reject_tags = csn.list_tags_for_resource(Arn=arn)["Tags"]
    assert after_reject_tags == {}, f"expected the rejected tag to leave the rule untagged, got {after_reject_tags!r}"

    # Positive control: a normal tag key on the same rule succeeds.
    result = csn.tag_resource(Arn=arn, Tags={"env": "sim2real-test"})
    assert result["Tags"] == {"env": "sim2real-test"}, f"expected TagResource to echo {{'env': 'sim2real-test'}}, got {result.get('Tags')!r}"
    final_tags = csn.list_tags_for_resource(Arn=arn)["Tags"]
    assert final_tags == {"env": "sim2real-test"}, f"expected ListTagsForResource to show {{'env': 'sim2real-test'}} after the positive control, got {final_tags!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
