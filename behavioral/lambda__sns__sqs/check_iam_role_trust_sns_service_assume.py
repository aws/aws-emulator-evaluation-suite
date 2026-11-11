"""iam-role-trust-sns-service-assume."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trust-sns-service-assume"
GROUP = "trust-policy"
SERVICES = ["lambda", "sns", "sqs"]

_LOGS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "*",
    }],
}
_PROPAGATION_CODES = frozenset({"AuthorizationError", "InvalidParameter"})
_PROPAGATION_S = 90.0


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting sns.amazonaws.com only with topic A as aws:SourceArn and its owner as
    aws:SourceAccount lets SNS write A's SUCCESS delivery record, while the same role is refused on
    sibling topic B with InvalidParameter and B's deliveries write no record."""
    iam = ctx.client("iam")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    logs = ctx.client("logs")

    scoped = _wired_topic(ctx, sns, sqs, logs, "sim2real-snsassume-scoped-")
    sibling = _wired_topic(ctx, sns, sqs, logs, "sim2real-snsassume-sibling-")
    role = _create_role(ctx, iam, "sim2real-snsassume-role-", {
        "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"ArnEquals": {"aws:SourceArn": scoped["topic"]},
                      "StringEquals": {"aws:SourceAccount": ctx.account}}})

    _set_feedback_role_with_retry(sns, scoped["topic"], role)
    got = sns.get_topic_attributes(TopicArn=scoped["topic"])["Attributes"]
    assert got.get("SQSSuccessFeedbackRoleArn") == role, (
        f"the role scoped to this topic must be its SQSSuccessFeedbackRoleArn; "
        f"got {got.get('SQSSuccessFeedbackRoleArn')!r}")

    # The role is already accepted on the scoped topic, so its refusal here is the SourceArn
    # condition's doing, not IAM propagation.
    error = _error(lambda: sns.set_topic_attributes(
        TopicArn=sibling["topic"], AttributeName="SQSSuccessFeedbackRoleArn", AttributeValue=role))
    assert error["Code"] == "InvalidParameter", (
        f"a role SNS may assume only for another topic must be refused with InvalidParameter; "
        f"got {error!r}")
    assert error["Message"] == (
        f"Invalid parameter: SQSSuccessFeedbackRoleArn: {role} is not a valid role to allow SNS "
        f"to write to Cloudwatch Logs"), f"unexpected refusal message {error['Message']!r}"
    got = sns.get_topic_attributes(TopicArn=sibling["topic"])["Attributes"]
    assert "SQSSuccessFeedbackRoleArn" not in got, (
        f"the refused role must not land on the sibling topic; SQSSuccessFeedbackRoleArn is "
        f"{got.get('SQSSuccessFeedbackRoleArn')!r}")

    blocked_mid = sns.publish(TopicArn=sibling["topic"],
                              Message=ctx.unique_name("sim2real-snsassume-sibling-"))["MessageId"]
    mid = sns.publish(TopicArn=scoped["topic"],
                      Message=ctx.unique_name("sim2real-snsassume-scoped-"))["MessageId"]

    latency, records = _latency(lambda: _records(logs, scoped["group"], mid), budget_s=150.0)
    assert len(records) == 1, (
        f"the scoped role must carry exactly one delivery record for MessageId {mid!r}; got {records!r}")
    record = records[0]
    assert record["status"] == "SUCCESS", f"expected status SUCCESS, got {record!r}"
    assert record["notification"]["topicArn"] == scoped["topic"], (
        f"the record must be the scoped topic's {scoped['topic']!r}; got {record['notification']!r}")
    assert record["delivery"]["destination"] == scoped["queue_arn"], (
        f"the record must name the scoped topic's queue {scoped['queue_arn']!r}; got {record['delivery']!r}")

    # The blocked Publish went out before the scoped one, so 2L more holds its absence >= 3L.
    seen = _absent_for(lambda: _records(logs, sibling["group"], None), latency, factor=2.0,
                       poll_s=2.0)
    assert seen == [], (
        f"the sibling topic, whose assume the condition refuses, must write no delivery record "
        f"within {max(10.0, 3 * latency):.0f}s; got {seen!r}")
    assert _delivered(sqs, sibling["queue_url"], blocked_mid, 60.0), (
        f"the refused role must not stop delivery: message {blocked_mid!r} never reached its queue")


# ===== helpers =====

def _error(fn) -> dict:
    """The Error ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own ``not_found`` codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 2.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _latency(observe, *, budget_s: float = 120.0, poll_s: float = 1.0):
    """``(seconds, result)`` until ``observe()`` first returns something truthy: the positive's L."""
    start = time.monotonic()
    while True:
        result = observe()
        if result:
            return time.monotonic() - start, result
        if time.monotonic() - start > budget_s:
            raise AssertionError(f"the positive control saw nothing in {budget_s}s")
        time.sleep(poll_s)


def _absent_for(observe, latency_s: float, *, factor: float = 3.0, floor_s: float = 10.0,
                poll_s: float = 1.0) -> list:
    """Everything ``observe()`` returned over ``max(floor_s, factor * latency_s)`` seconds."""
    window = max(floor_s, factor * latency_s)
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


def _create_role(ctx, iam, prefix: str, statement: dict) -> str:
    """A role whose trust is ``statement``, with the logs permissions delivery-status logging needs."""
    name = ctx.unique_name(prefix)
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="logs", PolicyDocument=json.dumps(_LOGS_POLICY))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="logs"),
                             "NoSuchEntity"))
    return arn


def _wired_topic(ctx, sns, sqs, logs, prefix: str) -> dict:
    """A topic with one subscribed queue, and the reap of the log group SNS may create for it."""
    name = ctx.unique_name(prefix)
    topic = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic), "NotFound"))
    group = f"sns/{ctx.region}/{ctx.account}/{name}"
    ctx.on_cleanup(lambda: _reap_log_group(logs, group))

    url = sqs.create_queue(QueueName=ctx.unique_name(f"{prefix}q-"), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(_teardown(lambda: sns.unsubscribe(SubscriptionArn=sub), "NotFound"))
    return {"topic": topic, "group": group, "queue_url": url, "queue_arn": queue_arn}


def _set_feedback_role_with_retry(sns, topic: str, role_arn: str) -> None:
    """Set the SQS success feedback role at 100% sampling. Until IAM has propagated the new role,
    SNS refuses it (PassRole, or the trust it cannot yet read); that refusal is retried, bounded."""
    deadline = time.monotonic() + _PROPAGATION_S
    while True:
        try:
            sns.set_topic_attributes(TopicArn=topic, AttributeName="SQSSuccessFeedbackRoleArn",
                                     AttributeValue=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _PROPAGATION_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    sns.set_topic_attributes(TopicArn=topic, AttributeName="SQSSuccessFeedbackSampleRate",
                             AttributeValue="100")


def _records(logs, group: str, message_id: str | None) -> list[dict]:
    """The delivery-status records in ``group`` (for ``message_id`` when given); [] if no group."""
    try:
        events = logs.filter_log_events(logGroupName=group).get("events", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return []
    records = [json.loads(e["message"]) for e in events]
    if message_id is None:
        return records
    return [r for r in records if r.get("notification", {}).get("messageId") == message_id]


def _delivered(sqs, queue_url: str, message_id: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if json.loads(msg["Body"]).get("MessageId") == message_id:
                return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
