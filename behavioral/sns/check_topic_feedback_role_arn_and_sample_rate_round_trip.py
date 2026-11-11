"""topic-feedback-role-arn-and-sample-rate-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-feedback-role-arn-and-sample-rate-round-trip"
GROUP = 'topic-attributes'
SERVICES = ['sns']

def _attrs(sns, arn):
    return sns.get_topic_attributes(TopicArn=arn)["Attributes"]


def _feedback_role(ctx, suffix):
    """A real IAM role SNS may assume to write CloudWatch Logs on its behalf. SetTopicAttributes
    checks the CALLER's iam:PassRole on this ARN, so the role itself only needs to exist and
    trust sns.amazonaws.com; nothing ever actually assumes it."""
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-behav-sns-fb-{suffix}-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}), Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _caller(ctx, topic_arn, passable_role_arns):
    """An SNS client signed as a role this check creates, which may SetTopicAttributes on
    ``topic_arn`` and pass every ARN in ``passable_role_arns``."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-sns-fb-caller-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "sts:AssumeRole"}]}), Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="set-feedback-attrs", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sns:SetTopicAttributes", "Resource": topic_arn},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": list(passable_role_arns)}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="set-feedback-attrs"))
    deadline = time.monotonic() + 90
    while True:
        try:
            creds = sts.assume_role(RoleArn=arn, RoleSessionName="sim2real-fb-caller")["Credentials"]
            break
        except ClientError as exc:
            # A just-created role's trust policy propagates; nothing to poll.
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    return ctx.client("sns", creds={"aws_access_key_id": creds["AccessKeyId"],
                                    "aws_secret_access_key": creds["SecretAccessKey"],
                                    "aws_session_token": creds["SessionToken"]})


def _set_with_retry(fn, deadline):
    """A fresh caller identity's own permissions (not the passed role's trust) propagate;
    retry AccessDenied/AuthorizationError until the deadline, then let it raise."""
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDenied", "AuthorizationError") or (
                    time.monotonic() > deadline):
                raise
            time.sleep(3)


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SQS and Lambda feedback attributes (SuccessFeedbackRoleArn, SuccessFeedbackSampleRate,
    FailureFeedbackRoleArn) round-trip independently: writing SQS's leaves Lambda's unset, and
    writing Lambda's leaves SQS's untouched, every value reading back exactly."""
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-feedback-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    success_role = _feedback_role(ctx, "ok")
    failure_role = _feedback_role(ctx, "err")
    # SetTopicAttributes checks the caller's iam:PassRole on the role ARN, so a dedicated caller
    # role holding that permission makes the writes.
    caller = _caller(ctx, topic_arn, [success_role, failure_role])
    deadline = time.monotonic() + 90

    def _set(name, value):
        _set_with_retry(lambda: caller.set_topic_attributes(
            TopicArn=topic_arn, AttributeName=name, AttributeValue=value), deadline)

    base = _attrs(sns, topic_arn)
    feedback_names = (
        "SQSSuccessFeedbackRoleArn", "SQSSuccessFeedbackSampleRate", "SQSFailureFeedbackRoleArn",
        "LambdaSuccessFeedbackRoleArn", "LambdaSuccessFeedbackSampleRate", "LambdaFailureFeedbackRoleArn",
    )
    present = sorted(n for n in feedback_names if n in base)
    assert not present, f"a new topic must report no feedback attributes until set, got {present!r}"

    sqs_writes = [
        ("SQSSuccessFeedbackRoleArn", success_role),
        ("SQSSuccessFeedbackSampleRate", "42"),
        ("SQSFailureFeedbackRoleArn", failure_role),
    ]
    for name, value in sqs_writes:
        _set(name, value)

    after_sqs = _attrs(sns, topic_arn)
    expected_sqs = dict(sqs_writes)
    seen_sqs = {k: after_sqs.get(k) for k in expected_sqs}
    assert seen_sqs == expected_sqs, (
        f"after the three SQS feedback writes, expected {expected_sqs!r}, got {seen_sqs!r}"
    )
    lambda_present = sorted(n for n in feedback_names if n.startswith("Lambda") and n in after_sqs)
    assert not lambda_present, (
        f"writing the SQS feedback attributes must not create any Lambda ones, got {lambda_present!r}"
    )

    lambda_writes = [
        ("LambdaSuccessFeedbackRoleArn", success_role),
        ("LambdaSuccessFeedbackSampleRate", "7"),
        ("LambdaFailureFeedbackRoleArn", failure_role),
    ]
    for name, value in lambda_writes:
        _set(name, value)

    final = _attrs(sns, topic_arn)
    expected_all = {**expected_sqs, **dict(lambda_writes)}
    seen_all = {k: final.get(k) for k in expected_all}
    assert seen_all == expected_all, (
        f"writing the Lambda feedback attributes must leave the earlier SQS ones untouched "
        f"and add its own; expected {expected_all!r}, got {seen_all!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
