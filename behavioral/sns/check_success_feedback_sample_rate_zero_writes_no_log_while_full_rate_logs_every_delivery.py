"""success-feedback-sample-rate-zero-writes-no-log-while-full-rate-logs-every-delivery."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "success-feedback-sample-rate-zero-writes-no-log-while-full-rate-logs-every-delivery"
GROUP = "delivery-status-logging"
SERVICES = ["sns"]


@tags("axis:happy-path", "cap:c4", "concern:metrics", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """At SQSSuccessFeedbackSampleRate=0 messages are still delivered but no log record is written;
    raising the rate to 100 logs exactly one SUCCESS record for the next delivery, while the
    rate-0 deliveries stay unlogged."""
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
    # A just-created role is not immediately assumable (IAM propagation) and SNS drops the log
    # record it cannot write, so a separate rate-100 topic proves the role writes records first.
    _await_role_logging(ctx, sns, sqs, logs, role_arn)

    topic_name = ctx.unique_name("sim2real-behav-sns-fbrate-")
    topic = _create_topic_with_role(ctx, sns, topic_name, role_arn, "0")
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    log_group = f"sns/{ctx.region}/{ctx.account}/{topic_name}"
    ctx.on_cleanup(lambda: _delete_log_group(logs, log_group))

    queue_url, queue_arn = _create_queue(ctx, sqs, "sim2real-behav-sns-fbrateq-")
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)

    zero_mid = sns.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-fb-zero-"))["MessageId"]
    assert _wait_delivered(ctx, sqs, queue_url, zero_mid, 60), (
        f"the message {zero_mid!r} must still be delivered at sample rate 0")

    one_mid = sns.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-fb-zero-2-"))["MessageId"]
    assert _wait_delivered(ctx, sqs, queue_url, one_mid, 60), (
        f"the message {one_mid!r} must still be delivered at sample rate 0")

    none_logged = _poll_log_events(ctx, logs, log_group, zero_mid, 0) + _poll_log_events(ctx, logs, log_group, one_mid, 0)
    assert none_logged == [], (
        f"at SQSSuccessFeedbackSampleRate=0 no record for either delivered message may exist; "
        f"got {none_logged!r}")

    sns.set_topic_attributes(TopicArn=topic, AttributeName="SQSSuccessFeedbackSampleRate", AttributeValue="100")
    full_mid = sns.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-fb-full-"))["MessageId"]
    assert _wait_delivered(ctx, sqs, queue_url, full_mid, 60), f"the message {full_mid!r} must be delivered at sample rate 100"
    full_records = _poll_log_events(ctx, logs, log_group, full_mid, 120)
    assert len(full_records) == 1, (
        f"at SQSSuccessFeedbackSampleRate=100 exactly one record must exist for {full_mid!r}; "
        f"got {len(full_records)} record(s)")
    assert full_records[0]["status"] == "SUCCESS", f"expected status SUCCESS, got {full_records[0]['status']!r}"

    # The sample-rate-0 deliveries are still absent after the rate-100 record has appeared,
    # confirming the earlier absence was not merely a race with log propagation.
    still_none = _poll_log_events(ctx, logs, log_group, zero_mid, 0) + _poll_log_events(ctx, logs, log_group, one_mid, 0)
    assert still_none == [], (
        f"the sample-rate-0 deliveries must never be logged, even after a later delivery is; got {still_none!r}")


def _create_queue(ctx, sqs, prefix: str) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _deadline(ctx, timeout_s: float) -> float:
    """A monotonic deadline ``timeout_s`` away, capped by the check's remaining run time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _create_topic_with_role(ctx, sns, name: str, role_arn: str, sample_rate: str) -> str:
    """CreateTopic with a just-created feedback role, retrying the iam:PassRole denial IAM
    propagation causes until it clears, bounded."""
    deadline = _deadline(ctx, 60)
    while True:
        try:
            return sns.create_topic(Name=name, Attributes={
                "SQSSuccessFeedbackRoleArn": role_arn, "SQSSuccessFeedbackSampleRate": sample_rate},
                Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
        except ClientError as exc:
            error = exc.response["Error"]
            if (error["Code"] != "AuthorizationError" or "iam:PassRole" not in error["Message"]
                    or time.monotonic() >= deadline):
                raise
            time.sleep(3)


def _await_role_logging(ctx, sns, sqs, logs, role_arn: str) -> None:
    """Publish probe messages to a rate-100 topic using role_arn every few seconds until one
    probe's SUCCESS record lands in that topic's log group."""
    name = ctx.unique_name("sim2real-behav-sns-fbprobe-")
    topic = _create_topic_with_role(ctx, sns, name, role_arn, "100")
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    log_group = f"sns/{ctx.region}/{ctx.account}/{name}"
    ctx.on_cleanup(lambda: _delete_log_group(logs, log_group))
    queue_url, queue_arn = _create_queue(ctx, sqs, "sim2real-behav-sns-fbprobeq-")
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)
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


def _wait_delivered(ctx, sqs, queue_url: str, message_id: str, timeout_s: float) -> bool:
    deadline = _deadline(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if json.loads(msg["Body"]).get("MessageId") == message_id:
                return True
    return False


def _delete_log_group(logs, log_group: str) -> None:
    try:
        logs.delete_log_group(logGroupName=log_group)
    except logs.exceptions.ResourceNotFoundException:
        pass


def _poll_log_events(ctx, logs, log_group: str, message_id: str, timeout_s: float) -> list[dict]:
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
