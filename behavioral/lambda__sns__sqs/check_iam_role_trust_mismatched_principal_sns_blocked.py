"""iam-role-trust-mismatched-principal-sns-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trust-mismatched-principal-sns-blocked"
GROUP = "trust-policy"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """SetTopicAttributes rejects a feedback role trusting lambda.amazonaws.com with
    InvalidParameter (exact message) and no delivery-status log is written, while a topic with a
    role trusting SNS is logged."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sns = ctx.client("sns")
    account_id = sts.get_caller_identity()["Account"]

    good_role_arn, _good_role_name = _make_feedback_role(ctx, iam, "sns.amazonaws.com")
    bad_role_arn, _bad_role_name = _make_feedback_role(ctx, iam, "lambda.amazonaws.com")

    good_topic_name = ctx.unique_name("sim2real-behav-goodfb-topic-")
    bad_topic_name = ctx.unique_name("sim2real-behav-badfb-topic-")
    good_topic_arn = sns.create_topic(Name=good_topic_name, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=good_topic_arn))
    bad_topic_arn = sns.create_topic(Name=bad_topic_name, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=bad_topic_arn))

    good_queue = _wire_queue_to_topic(ctx, good_topic_arn)
    bad_queue = _wire_queue_to_topic(ctx, bad_topic_arn)

    # role propagation is eventually consistent: retry a bounded window rather
    # than trust a fixed sleep to have outlasted it.
    _set_feedback_role_with_retry(sns, good_topic_arn, good_role_arn)

    # SNS validates at configuration time that the feedback role's trust
    # policy actually allows sns.amazonaws.com to assume it -- a role that
    # instead trusts lambda.amazonaws.com is rejected immediately by
    # SetTopicAttributes, before any message is ever published.
    try:
        sns.set_topic_attributes(
            TopicArn=bad_topic_arn,
            AttributeName="SQSSuccessFeedbackRoleArn",
            AttributeValue=bad_role_arn,
        )
    except ClientError as err:
        raised = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
    else:
        raise AssertionError(
            "SetTopicAttributes accepted a feedback role trusting lambda.amazonaws.com "
            "instead of sns.amazonaws.com"
        )
    assert raised == "InvalidParameter", (
        "role trusting lambda.amazonaws.com instead of sns.amazonaws.com should be "
        f"rejected as an SNS feedback role, but got: {raised}"
    )
    expected = (
        f"Invalid parameter: SQSSuccessFeedbackRoleArn: {bad_role_arn} "
        "is not a valid role to allow SNS to write to Cloudwatch Logs"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    sns.publish(TopicArn=good_topic_arn, Message="control-should-log")
    sns.publish(TopicArn=bad_topic_arn, Message="mismatched-should-not-log")

    good_log_group = f"sns/{ctx.region}/{account_id}/{good_topic_name}"
    bad_log_group = f"sns/{ctx.region}/{account_id}/{bad_topic_name}"

    good_events = _wait_log_events(ctx, good_log_group, timeout_s=150.0)
    assert good_events, "positive control: expected delivery-status logs, found none"

    bad_events = _wait_log_events(ctx, bad_log_group, timeout_s=30.0)
    assert bad_events == [], (
        "role trusting lambda.amazonaws.com should never be assumable by SNS, "
        f"but delivery logs appeared: {bad_events}"
    )

    # both messages nonetheless reached their queues (feedback role only
    # affects logging, never message delivery itself)
    sqs = ctx.client("sqs")
    for q in (good_queue, bad_queue):
        msgs = _receive_all(sqs, q["url"])
        assert len(msgs) == 1, (
            f"expected exactly 1 message delivered to queue {q['url']!r} regardless of "
            f"feedback role config, got {len(msgs)}"
        )

    # No restore leg: measured on real AWS, repairing bad_role's trust policy in place
    # (update_assume_role_policy) does NOT unblock the identical SetTopicAttributes call within a
    # 90s retry window -- it keeps returning the same InvalidParameter. SNS's feedback-role
    # validation appears to cache the negative decision per role ARN well past ordinary IAM trust
    # propagation, so a bounded restore-and-retry is not achievable inside this check's 300s budget.


_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:check": CHECK}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _trust_doc(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
        ],
    }


def _set_feedback_role_with_retry(
    sns, topic_arn: str, role_arn: str, timeout_s: float = 90.0, interval_s: float = 5.0
) -> None:
    """Trust-policy propagation is eventually consistent: retry a bounded
    window on the transient rejection codes rather than trust a fixed sleep to
    have outlasted it. Any other error is a real defect and propagates."""
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
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("AuthorizationError", "InvalidParameter", "InvalidParameterValue"):
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(
        f"feedback role {role_arn!r} on topic {topic_arn!r} never became assumable within "
        f"{timeout_s}s: {last_err}"
    )


def _make_feedback_role(ctx, iam, principal: str) -> tuple[str, str]:
    role_name = ctx.unique_name("sim2real-behav-fbrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc(principal)),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"))
    return role_arn, role_name


def _wire_queue_to_topic(ctx, topic_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-fbq-"), tags=_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return {"url": url, "arn": arn}


def _receive_all(sqs, url: str, timeout_s: float = 30.0):
    out = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(out) < 1:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _wait_log_events(ctx, log_group: str, timeout_s: float = 150.0, interval_s: float = 5.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            streams = logs.describe_log_streams(logGroupName=log_group)["logStreams"]
        except logs.exceptions.ResourceNotFoundException:
            streams = []
        for stream in streams:
            resp = logs.get_log_events(
                logGroupName=log_group, logStreamName=stream["logStreamName"]
            )
            if resp["events"]:
                return resp["events"]
        time.sleep(interval_s)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
