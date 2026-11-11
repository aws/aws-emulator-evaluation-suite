"""iam-role-trust-sns-principal."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trust-sns-principal"
GROUP = "iam-trust"
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


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting {"Service": ["lambda.amazonaws.com", "sns.amazonaws.com"]} lets SNS write a
    SUCCESS delivery record, while the service name under the AWS key and the regional SNS name are
    refused with MalformedPolicyDocument and the refused update leaves the working trust in force."""
    iam = ctx.client("iam")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    logs = ctx.client("logs")

    role_name, role = _create_role(
        ctx, iam, "sim2real-iamtrust-role-",
        {"Service": ["lambda.amazonaws.com", "sns.amazonaws.com"]})
    wired = _wired_topic(ctx, sns, sqs, logs, "sim2real-iamtrust-topic-")
    _set_feedback_role_with_retry(sns, wired["topic"], role)

    first = sns.publish(TopicArn=wired["topic"], Message=ctx.unique_name("sim2real-iamtrust-1-"))["MessageId"]
    _latency(lambda: _records(logs, wired["group"], first), budget_s=150.0)

    aws_form = ctx.unique_name("sim2real-iamtrust-awsform-")
    error = _error(lambda: _create_role_once(ctx, iam, aws_form, {"AWS": "sns.amazonaws.com"}))
    assert error["Code"] == "MalformedPolicyDocument", (
        f"a service name under the AWS principal key must be refused with "
        f"MalformedPolicyDocument; got {error!r}")
    assert error["Message"] == 'Invalid principal in policy: "AWS":"sns.amazonaws.com"', (
        f"unexpected refusal message {error['Message']!r}")
    missing = _error(lambda: iam.get_role(RoleName=aws_form))
    assert missing["Code"] == "NoSuchEntity", f"the refused CreateRole must leave no role; got {missing!r}"

    regional = f"sns.{ctx.region}.amazonaws.com"
    error = _error(lambda: iam.update_assume_role_policy(
        RoleName=role_name, PolicyDocument=json.dumps(_trust({"Service": regional}))))
    assert error["Code"] == "MalformedPolicyDocument", (
        f"the regional SNS service name must be refused with MalformedPolicyDocument; got {error!r}")
    assert error["Message"] == f'Invalid principal in policy: "SERVICE":"{regional}"', (
        f"unexpected refusal message {error['Message']!r}")

    second = sns.publish(TopicArn=wired["topic"], Message=ctx.unique_name("sim2real-iamtrust-2-"))["MessageId"]
    _, records = _latency(lambda: _records(logs, wired["group"], second), budget_s=150.0)
    assert len(records) == 1, (
        f"after the refused trust update SNS must still write exactly one record for MessageId "
        f"{second!r}; got {records!r}")
    record = records[0]
    assert record["status"] == "SUCCESS", f"expected status SUCCESS, got {record!r}"
    assert record["delivery"]["destination"] == wired["queue_arn"], (
        f"the record must name the subscribed queue {wired['queue_arn']!r}; got {record['delivery']!r}")
    assert record["delivery"]["statusCode"] == 200, (
        f"a successful SQS delivery's record must carry statusCode 200; got {record['delivery']!r}")


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


def _trust(principal: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}]}


def _create_role_once(ctx, iam, name: str, principal: dict) -> str:
    """Create role ``name`` trusting ``principal``; a created role is torn down even when the
    caller expected a refusal."""
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_trust(principal)),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_role(ctx, iam, prefix: str, principal: dict) -> tuple[str, str]:
    """(name, ARN) of a role trusting ``principal`` with the logs permissions delivery-status
    logging needs."""
    name = ctx.unique_name(prefix)
    arn = _create_role_once(ctx, iam, name, principal)
    iam.put_role_policy(RoleName=name, PolicyName="logs", PolicyDocument=json.dumps(_LOGS_POLICY))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="logs"),
                             "NoSuchEntity"))
    return name, arn


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
