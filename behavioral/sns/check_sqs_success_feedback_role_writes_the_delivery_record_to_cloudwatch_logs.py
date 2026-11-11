"""sqs-success-feedback-role-writes-the-delivery-record-to-cloudwatch-logs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-success-feedback-role-writes-the-delivery-record-to-cloudwatch-logs"
GROUP = "delivery-status-logging"
SERVICES = ["sns"]


@tags("axis:happy-path", "cap:c4", "concern:metrics", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SQSSuccessFeedbackRoleArn at sample rate 100 makes SNS write exactly one log record per SQS
    delivery to sns/<region>/<account-id>/<topic-name>, naming the MessageId, topic, queue ARN,
    status SUCCESS and statusCode 200."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-sns-fbrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"))

    topic_name = ctx.unique_name("sim2real-behav-sns-fblog-")
    topic = _create_topic_with_role(ctx, sns, topic_name, role_arn)
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))

    queue_name = ctx.unique_name("sim2real-behav-sns-fbq-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)

    log_group = f"sns/{ctx.region}/{ctx.account}/{topic_name}"
    ctx.on_cleanup(lambda: _delete_log_group(logs, log_group))

    # A just-created role is not immediately assumable (IAM propagation) and SNS drops the log
    # record it cannot write, so probe messages are published until one is logged.
    _await_feedback_logging(ctx, sns, logs, topic, log_group)

    mid = sns.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-fb-success-"))["MessageId"]

    # The log record is written asynchronously after delivery, so wait for delivery first.
    deadline = _deadline(ctx, 120)
    delivered = False
    while time.monotonic() < deadline and not delivered:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            if json.loads(msg["Body"]).get("MessageId") == mid:
                delivered = True
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    assert delivered, f"the published message {mid!r} never reached the subscribed queue"

    events = _poll_log_events(ctx, logs, log_group, mid, 120)
    assert len(events) == 1, (
        f"the success feedback log group must carry exactly one record for MessageId {mid!r}; "
        f"got {len(events)} record(s)")
    record = events[0]
    assert record["status"] == "SUCCESS", f"expected status SUCCESS, got {record['status']!r}"
    assert record["notification"]["messageId"] == mid, (
        f"the log record's notification.messageId must be the Publish's MessageId {mid!r}; "
        f"got {record['notification'].get('messageId')!r}")
    assert record["notification"]["topicArn"] == topic, (
        f"the log record's notification.topicArn must be {topic!r}; got {record['notification'].get('topicArn')!r}")
    assert record["delivery"]["destination"] == queue_arn, (
        f"the log record's delivery.destination must be the subscribed queue {queue_arn!r}; "
        f"got {record['delivery'].get('destination')!r}")
    assert record["delivery"]["statusCode"] == 200, (
        f"a successful SQS delivery's log record must carry statusCode 200; got {record['delivery'].get('statusCode')!r}")


def _create_topic_with_role(ctx, sns, topic_name: str, role_arn: str) -> str:
    """CreateTopic checks the caller's iam:PassRole on role_arn, which a just-created role fails
    until IAM propagates it; that refusal is retried, bounded."""
    deadline = _deadline(ctx, 60)
    while True:
        try:
            return sns.create_topic(Name=topic_name, Attributes={
                "SQSSuccessFeedbackRoleArn": role_arn, "SQSSuccessFeedbackSampleRate": "100"},
                Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
        except ClientError as exc:
            error = exc.response["Error"]
            if (error["Code"] != "AuthorizationError" or "iam:PassRole" not in error["Message"]
                    or time.monotonic() >= deadline):
                raise
            time.sleep(3)


def _delete_log_group(logs, log_group: str) -> None:
    try:
        logs.delete_log_group(logGroupName=log_group)
    except logs.exceptions.ResourceNotFoundException:
        pass


def _deadline(ctx, timeout_s: float) -> float:
    """A monotonic deadline ``timeout_s`` away, capped by the check's remaining run time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _await_feedback_logging(ctx, sns, logs, topic: str, log_group: str) -> None:
    """Publish a probe message every few seconds until one probe's record lands in log_group."""
    deadline = _deadline(ctx, 120)
    probes: set[str] = set()
    next_probe_at = time.monotonic()
    while True:
        if time.monotonic() >= next_probe_at:
            probes.add(sns.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-fb-probe-"))["MessageId"])
            next_probe_at = time.monotonic() + 10
        try:
            events = logs.filter_log_events(logGroupName=log_group).get("events", [])
        except logs.exceptions.ResourceNotFoundException:
            events = []
        if any(json.loads(e["message"]).get("notification", {}).get("messageId") in probes for e in events):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"no delivery status record for {len(probes)} probe message(s) reached {log_group}")
        time.sleep(2)


def _poll_log_events(ctx, logs, log_group: str, message_id: str, timeout_s: float) -> list[dict]:
    """Every delivery-status record in log_group whose notification.messageId is message_id,
    polled until the group exists and the feedback record has been written."""
    deadline = _deadline(ctx, timeout_s)
    while True:
        try:
            resp = logs.filter_log_events(logGroupName=log_group)
            records = [json.loads(e["message"]) for e in resp.get("events", [])]
            matches = [r for r in records if r.get("notification", {}).get("messageId") == message_id]
            if matches or time.monotonic() >= deadline:
                return matches
        except logs.exceptions.ResourceNotFoundException:
            if time.monotonic() >= deadline:
                return []
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
