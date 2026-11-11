"""set-topic-attributes-cross-account-feedback-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-topic-attributes-cross-account-feedback-role-rejected"
GROUP = "delivery-status-logging"
SERVICES = ["sns"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A *FeedbackRoleArn naming a role in another account is refused as a cross-account PassRole,
    whatever the role's path; the same attribute naming this account's own role is accepted."""
    sns = ctx.client("sns")
    iam = ctx.client("iam")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-feedback-xacct-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))

    other_account = "123456789012" if ctx.account != "123456789012" else "123456789013"
    foreign_role = f"arn:aws:iam::{other_account}:role/sim2real-behav-sns-not-ours"
    attr = "SQSFailureFeedbackRoleArn"
    code, msg = _error(lambda: sns.set_topic_attributes(
        TopicArn=topic, AttributeName=attr, AttributeValue=foreign_role))
    assert code == "AuthorizationError", f"expected AuthorizationError, got {code!r}: {msg!r}"
    assert msg == "Cross-account pass role is not allowed.", (
        f"the cross-account refusal must carry this exact message; got {msg!r}")
    assert attr not in sns.get_topic_attributes(TopicArn=topic)["Attributes"], (
        "a rejected cross-account SetTopicAttributes must not set the attribute")

    # Positive control: the same attribute, naming a role this check owns in this account.
    role_name = ctx.unique_name("sim2real-behav-sns-feedback-xacct-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # A just-created role is not immediately recognized for iam:PassRole (IAM propagation), so
    # the AuthorizationError is retried until a deadline capped by the remaining run time.
    left = ctx.time_left()
    deadline = time.monotonic() + (70 if left is None else min(70, left))
    while True:
        try:
            sns.set_topic_attributes(TopicArn=topic, AttributeName=attr, AttributeValue=role_arn)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AuthorizationError" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    got = sns.get_topic_attributes(TopicArn=topic)["Attributes"].get(attr)
    assert got == role_arn, f"this account's own role ARN must read back verbatim; got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
