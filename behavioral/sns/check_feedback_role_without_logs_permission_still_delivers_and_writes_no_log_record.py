"""feedback-role-without-logs-permission-still-delivers-and-writes-no-log-record."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feedback-role-without-logs-permission-still-delivers-and-writes-no-log-record"
GROUP = "delivery-status-logging"
SERVICES = ["sns"]

_CONTROL_ATTEMPTS = 3
_CONTROL_LOG_WAIT_S = 45
_PASS_ROLE_WAIT_S = 60


@tags("axis:happy-path", "cap:c4", "concern:metrics", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A feedback role without CloudWatch Logs permissions does not block delivery and creates no
    sns/<region>/<account>/<topic> log group; a twin role with logs permissions writes a SUCCESS
    record, proving the logging path fires.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    # Twin roles, identical except that only the permitted one may write logs.
    denied_role = _create_feedback_role(ctx, iam, "sim2real-behav-sns-fbrole-", logs_policy=False)
    permitted_role = _create_feedback_role(ctx, iam, "sim2real-behav-sns-fbokrole-", logs_policy=True)

    denied_name, denied_topic, denied_queue = _wired_topic(
        ctx, sns, sqs, logs, "sim2real-behav-sns-fbnoperm-", denied_role)
    permitted_name, permitted_topic, permitted_queue = _wired_topic(
        ctx, sns, sqs, logs, "sim2real-behav-sns-fbokperm-", permitted_role)
    denied_group = f"sns/{ctx.region}/{ctx.account}/{denied_name}"
    permitted_group = f"sns/{ctx.region}/{ctx.account}/{permitted_name}"

    # Positive control, and the bounded retry that absorbs IAM propagation for both roles: the
    # permitted twin's SUCCESS record must appear for one of a few publishes.
    record = None
    for attempt in range(_CONTROL_ATTEMPTS):
        control = sns.publish(TopicArn=permitted_topic,
                              Message=ctx.unique_name(f"sim2real-fb-ok-{attempt}-"))["MessageId"]
        assert _wait_delivered(sqs, permitted_queue, control, 60), (
            f"the permitted twin's message {control!r} never reached its queue")
        found = _poll_log_events(logs, permitted_group, control, _CONTROL_LOG_WAIT_S)
        if found:
            record = found[0]
            break
    assert record is not None, (
        f"the permitted twin (a feedback role WITH logs permissions) wrote no delivery record to "
        f"{permitted_group!r} for any of {_CONTROL_ATTEMPTS} publishes")
    assert record["status"] == "SUCCESS", (
        f"the permitted twin's delivery record must be status SUCCESS; got {record!r}")

    mid = sns.publish(TopicArn=denied_topic, Message=ctx.unique_name("sim2real-fb-noperm-"))["MessageId"]
    assert _wait_delivered(sqs, denied_queue, mid, 60), (
        f"the message {mid!r} must still be delivered when the feedback role cannot write logs")

    stuck = _poll_log_events(logs, denied_group, mid, 30)
    assert stuck == [], (
        f"a feedback role with no logs permissions must produce no log record; got {stuck!r}")
    groups = logs.describe_log_groups(logGroupNamePrefix=denied_group)["logGroups"]
    assert groups == [], (
        f"a feedback role with no logs permissions must create no log group under "
        f"{denied_group!r}; found {[g['logGroupName'] for g in groups]!r}")


def _create_feedback_role(ctx, iam, prefix: str, *, logs_policy: bool) -> str:
    role_name = ctx.unique_name(prefix)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if logs_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*"}]}))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"))
    return role_arn


def _wired_topic(ctx, sns, sqs, logs, prefix: str, role_arn: str) -> tuple[str, str, str]:
    """(topic name, topic ARN, queue URL): a topic logging SQS successes through ``role_arn``,
    with one subscribed queue."""
    topic_name = ctx.unique_name(prefix)
    # CreateTopic checks iam:PassRole on the feedback role, which a just-created role fails until
    # IAM propagates it; that refusal is retried, bounded.
    deadline = time.monotonic() + _PASS_ROLE_WAIT_S
    while True:
        try:
            topic = sns.create_topic(Name=topic_name, Attributes={
                "SQSSuccessFeedbackRoleArn": role_arn, "SQSSuccessFeedbackSampleRate": "100"},
                Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
            break
        except ClientError as exc:
            error = exc.response["Error"]
            if (error["Code"] != "AuthorizationError" or "iam:PassRole" not in error["Message"]
                    or time.monotonic() >= deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    log_group = f"sns/{ctx.region}/{ctx.account}/{topic_name}"
    ctx.on_cleanup(lambda: _delete_log_group(logs, log_group))

    queue_url, queue_arn = _create_queue(ctx, sqs, f"{prefix}q-")
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
    return topic_name, topic, queue_url


def _create_queue(ctx, sqs, prefix: str) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _wait_delivered(sqs, queue_url: str, message_id: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
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


def _poll_log_events(logs, log_group: str, message_id: str, timeout_s: float) -> list[dict]:
    deadline = time.monotonic() + timeout_s
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
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
