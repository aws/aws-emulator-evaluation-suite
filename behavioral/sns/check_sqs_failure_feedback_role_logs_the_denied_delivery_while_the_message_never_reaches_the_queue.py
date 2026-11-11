"""sqs-failure-feedback-role-logs-the-denied-delivery-while-the-message-never-reaches-the-queue."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-failure-feedback-role-logs-the-denied-delivery-while-the-message-never-reaches-the-queue"
GROUP = "delivery-status-logging"
SERVICES = ["sns"]


@tags("axis:negative-delivery", "cap:c4", "concern:metrics", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With SQSFailureFeedbackRoleArn set, a queue whose policy denies SNS SendMessage gets a
    FAILURE log (AccessDenied, 403) in sns/<region>/<account>/<topic>/Failure and never the
    message, while a granting queue on the same topic receives it and is logged SUCCESS."""
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

    topic_name = ctx.unique_name("sim2real-behav-sns-fbfail-")
    # The caller's iam:PassRole on role_arn, just created, is a bounded retry on its first use.
    topic = _create_topic_with_retry(ctx, sns, topic_name, {
        "SQSFailureFeedbackRoleArn": role_arn,
        "SQSSuccessFeedbackRoleArn": role_arn, "SQSSuccessFeedbackSampleRate": "100"})
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))

    success_log_group = f"sns/{ctx.region}/{ctx.account}/{topic_name}"
    failure_log_group = f"{success_log_group}/Failure"
    ctx.on_cleanup(lambda: _delete_log_group(logs, success_log_group))
    ctx.on_cleanup(lambda: _delete_log_group(logs, failure_log_group))

    denied_url, denied_arn = _create_queue(ctx, sqs, "sim2real-behav-sns-fbdenied-")
    # Deliberately no queue policy granting sns.amazonaws.com sqs:SendMessage.
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=denied_arn)

    granted_url, granted_arn = _create_queue(ctx, sqs, "sim2real-behav-sns-fbgranted-")
    sqs.set_queue_attributes(QueueUrl=granted_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": granted_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=granted_arn)

    # A just-created role is not immediately assumable (IAM propagation) and SNS drops the log
    # record it cannot write, so probe messages are published until one is logged FAILURE.
    _await_feedback_logging(ctx, sns, logs, topic, failure_log_group)

    mid = sns.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-fb-denied-"))["MessageId"]

    # Terminal signal for the granted leg: the message actually lands in its queue.
    assert _wait_delivered(ctx, sqs, granted_url, mid, 120), (
        f"the published message {mid!r} never reached the queue whose policy grants SendMessage")

    failures = _poll_log_events(ctx, logs, failure_log_group, mid, 120)
    assert len(failures) == 1, (
        f"the failure feedback log group must carry exactly one record for MessageId {mid!r}; "
        f"got {len(failures)} record(s)")
    record = failures[0]
    assert record["status"] == "FAILURE", f"expected status FAILURE, got {record['status']!r}"
    assert record["delivery"]["destination"] == denied_arn, (
        f"the failure record's delivery.destination must be the denied queue {denied_arn!r}; "
        f"got {record['delivery'].get('destination')!r}")
    assert record["delivery"]["statusCode"] == 403, (
        f"a denied SendMessage's log record must carry statusCode 403; got {record['delivery'].get('statusCode')!r}")
    provider = json.loads(record["delivery"]["providerResponse"])
    assert provider["ErrorCode"] == "AccessDenied", (
        f"the failure record's provider response must name AccessDenied; got {provider.get('ErrorCode')!r}")
    assert provider["ErrorMessage"] == (
        f"User: sns.amazonaws.com is not authorized to perform: sqs:sendmessage on resource: "
        f"{denied_arn} because no resource-based policy allows the sqs:sendmessage action"), (
        f"the provider response's ErrorMessage must name this exact denied queue; got {provider['ErrorMessage']!r}")

    # The denied queue never received the message; the granted queue's success is separately logged.
    never = sqs.receive_message(QueueUrl=denied_url, MaxNumberOfMessages=10, WaitTimeSeconds=1).get("Messages", [])
    assert not any(json.loads(m["Body"]).get("MessageId") == mid for m in never), (
        "a message a queue policy denied must never reach that queue"
    )
    successes = _poll_log_events(ctx, logs, success_log_group, mid, 60)
    assert any(r["status"] == "SUCCESS" and r["delivery"]["destination"] == granted_arn for r in successes), (
        f"the granted queue's delivery must be logged SUCCESS in the same topic's success log group; got {successes!r}")


def _create_queue(ctx, sqs, prefix: str) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _deadline(ctx, timeout_s: float) -> float:
    """A monotonic deadline ``timeout_s`` away, capped by the check's remaining run time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _create_topic_with_retry(ctx, sns, topic_name: str, attributes: dict) -> str:
    """CreateTopic with freshly-created feedback role ARNs, retried on AuthorizationError until
    the caller's iam:PassRole on the new role has propagated."""
    deadline = _deadline(ctx, 60)
    while True:
        try:
            return sns.create_topic(Name=topic_name, Attributes=attributes,
                                     Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AuthorizationError" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


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
