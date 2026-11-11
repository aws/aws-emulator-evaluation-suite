"""iam-trust-sns-wrong-principal-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-trust-sns-wrong-principal-negative"
GROUP = "iam-trust"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetTopicAttributes accepts an SQS delivery-status feedback role trusting sns.amazonaws.com and reads
    it back, while a role trusting ec2.amazonaws.com is rejected (AuthorizationError or InvalidParameter) on
    every retry across the same propagation window and never appears in GetTopicAttributes."""
    iam = ctx.client("iam")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    log_perms = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }],
    }

    _good_role_name, good_role_arn = _create_role(
        ctx, iam, trust_principals=["sns.amazonaws.com"], inline_policy=log_perms
    )
    _bad_role_name, bad_role_arn = _create_role(
        ctx, iam, trust_principals=["ec2.amazonaws.com"], inline_policy=log_perms
    )

    good_topic_name = ctx.unique_name("sim2real-iamtrust-goodtopic-")
    bad_topic_name = ctx.unique_name("sim2real-iamtrust-badtopic-")
    topic_tags = [{"Key": "sim2real-check", "Value": CHECK}]
    good_topic_arn = sns.create_topic(Name=good_topic_name, Tags=topic_tags)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=good_topic_arn))
    bad_topic_arn = sns.create_topic(Name=bad_topic_name, Tags=topic_tags)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=bad_topic_arn))

    _subscribe_queue_to_topic(ctx, sns, sqs, good_topic_arn)
    _subscribe_queue_to_topic(ctx, sns, sqs, bad_topic_arn)

    # Positive control: a role that genuinely trusts sns.amazonaws.com is accepted
    # once IAM's trust-policy write has propagated.
    _set_feedback_role_with_retry(sns, good_topic_arn, good_role_arn)
    good_attrs = sns.get_topic_attributes(TopicArn=good_topic_arn)["Attributes"]
    assert good_attrs.get("SQSSuccessFeedbackRoleArn") == good_role_arn, (
        f"positive control: GetTopicAttributes shows SQSSuccessFeedbackRoleArn="
        f"{good_attrs.get('SQSSuccessFeedbackRoleArn')!r}, expected {good_role_arn!r}"
    )

    # Negative: a role trusting ec2.amazonaws.com is never assumable by SNS,
    # so every retry within the same propagation window still fails.
    rejected = _set_feedback_role_rejected(sns, bad_topic_arn, bad_role_arn)
    assert rejected, (
        "SetTopicAttributes accepted a feedback role trusting ec2.amazonaws.com "
        "instead of sns.amazonaws.com"
    )
    # Independent read at the destination: the rejected call must never have taken
    # hold of the topic's configuration, not merely raised on its own response.
    bad_attrs = sns.get_topic_attributes(TopicArn=bad_topic_arn)["Attributes"]
    assert bad_attrs.get("SQSSuccessFeedbackRoleArn", "") != bad_role_arn, (
        f"GetTopicAttributes shows SQSSuccessFeedbackRoleArn={bad_attrs.get('SQSSuccessFeedbackRoleArn')!r} "
        "== the wrong-principal role, even though SetTopicAttributes reported rejection"
    )


def _create_role(ctx, iam, trust_principals, managed_policy_arns=None, inline_policy=None):
    role_name = ctx.unique_name("sim2real-iamtrust-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": p}, "Action": "sts:AssumeRole"}
            for p in trust_principals
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    attached: list[str] = []
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        attached.append(policy_arn)
    inline_name = None
    if inline_policy:
        inline_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name, PolicyName=inline_name, PolicyDocument=json.dumps(inline_policy)
        )

    def _cleanup():
        if inline_name:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=inline_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for pa in attached:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pa)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


def _subscribe_queue_to_topic(ctx, sns, sqs, topic_arn):
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-iamtrust-q-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=arn)
    sub_arn = sub.get("SubscriptionArn")
    if sub_arn and sub_arn != "pending confirmation":
        ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return {"url": url, "arn": arn}


def _set_feedback_role_with_retry(sns, topic_arn, role_arn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            sns.set_topic_attributes(
                TopicArn=topic_arn, AttributeName="SQSSuccessFeedbackRoleArn", AttributeValue=role_arn
            )
            sns.set_topic_attributes(
                TopicArn=topic_arn, AttributeName="SQSSuccessFeedbackSampleRate", AttributeValue="100"
            )
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "AuthorizationError":
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None, "retry loop exited with no ClientError recorded"
    raise last_err


_REJECTION_CODES = ("AuthorizationError", "InvalidParameter", "InvalidParameterException")


def _set_feedback_role_rejected(sns, topic_arn, role_arn, timeout_s: float = 90.0, interval_s: float = 5.0) -> bool:
    """Retry the same window as the positive control; return True only if every
    single attempt was rejected -- either with AuthorizationError (SNS refusing to
    assume the wrongly-trusted role) or InvalidParameter (SNS rejecting the role ARN
    outright once it resolves the trust mismatch) -- and never a success."""
    deadline = time.monotonic() + timeout_s
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            sns.set_topic_attributes(
                TopicArn=topic_arn, AttributeName="SQSSuccessFeedbackRoleArn", AttributeValue=role_arn
            )
            sns.set_topic_attributes(
                TopicArn=topic_arn, AttributeName="SQSSuccessFeedbackSampleRate", AttributeValue="100"
            )
            return False
        except ClientError as e:
            if e.response["Error"]["Code"] not in _REJECTION_CODES:
                raise
            time.sleep(interval_s)
    return attempts > 0


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

