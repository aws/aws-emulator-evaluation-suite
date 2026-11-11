"""subscriber-on-failure-configuration-writes-dead-letter-record-to-sqs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscriber-on-failure-configuration-writes-dead-letter-record-to-sqs"
GROUP = "subscriber-delivery"
SERVICES = ["eventbridgev2", "sqs", "iam"]

_ACTIVE_TIMEOUT_S = 60.0
_DLQ_TIMEOUT_S = 120.0
_IAM_PROPAGATION_S = 10.0


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_bus_active(ebv2, bus_arn: str) -> None:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        if described["State"] == "ACTIVE":
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"bus stayed {described['State']!r}, never reached ACTIVE")
        time.sleep(2)


def _create_queue(ctx, sqs):
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-ebv2-q-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn}]})})
    return url, arn


def _create_role(ctx, iam, send_to_arns: list[str]) -> str:
    name = ctx.unique_name("sim2real-behav-ebv2-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="send-to-queues", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": send_to_arns}]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="send-to-queues"),
                             "NoSuchEntity"))
    return arn


def _poll_dlq_for_failure_record(sqs, dlq_url: str, event_id: str) -> dict:
    """Receive from ``dlq_url`` until a record naming ``event_id`` arrives; return its body."""
    deadline = time.monotonic() + _DLQ_TIMEOUT_S
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(
            QueueUrl=dlq_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=msg["ReceiptHandle"])
            failed = body.get("failedMessages", [])
            if any(f.get("eventId") == event_id for f in failed):
                return body
    raise AssertionError(f"no dead-letter record naming eventId {event_id!r} arrived within {_DLQ_TIMEOUT_S}s")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A subscriber whose target invocation fails writes one JSON failure record, not the
    original event, to the SQS queue named in OnFailureConfiguration.Arn.

    Reference: https://docs.aws.amazon.com/eventbridgev2/latest/userguide/eb-custom-bus-retry.html
    """
    ebv2 = ctx.client("eventbridgev2")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")
    sub_name = ctx.unique_name("sim2real-behav-ebv2-sub-")
    source = ctx.unique_name("sim2real.ebv2.")

    bus = ebv2.create_event_bus(Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown(lambda: ebv2.delete_event_bus(EventBusArn=bus_arn),
                             "ResourceNotFoundException"))
    _wait_bus_active(ebv2, bus_arn)

    target_url, target_arn = _create_queue(ctx, sqs)
    dlq_url, dlq_arn = _create_queue(ctx, sqs)
    role_arn = _create_role(ctx, iam, [target_arn, dlq_arn])

    # fixed-wait: IAM role-policy propagation exposes no condition to poll, and EventBridge
    # itself assumes the role, so this check has no call of its own to retry on AccessDenied.
    time.sleep(_IAM_PROPAGATION_S)

    sub = ebv2.create_subscriber(
        Name=sub_name, EventBusArn=bus_arn, ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        InvokeConfiguration={"RoleArn": role_arn, "TargetArn": target_arn, "SqsParameters": {}},
        RetryPolicy={"MaxRetryAttempts": 0},
        OnFailureConfiguration={"Arn": dlq_arn},
    )
    sub_arn = sub["SubscriberArn"]
    ctx.on_cleanup(_teardown(lambda: ebv2.delete_subscriber(SubscriberArn=sub_arn),
                             "ResourceNotFoundException"))
    assert sub["State"] == "RUNNING", f"expected a fresh subscriber to be RUNNING, got {sub['State']!r}"

    # The target queue is gone before any delivery attempt, so the one invocation this
    # subscriber ever makes fails deterministically.
    sqs.delete_queue(QueueUrl=target_url)

    put = ebv2.put_events(EventBusArn=bus_arn, Entries=[{
        "Source": source, "DetailType": "sim2real-ebv2-dlq-test",
        "Detail": json.dumps({"should-not": "appear-in-the-dead-letter-record"}),
    }])
    assert put["FailedEntryCount"] == 0, f"PutEvents itself failed: {put['Entries']!r}"
    event_id = put["Entries"][0]["EventId"]

    record = _poll_dlq_for_failure_record(sqs, dlq_url, event_id)

    assert record["busArn"] == bus_arn, f"record busArn {record['busArn']!r} != {bus_arn!r}"
    assert record["subscriberArn"] == sub_arn, (
        f"record subscriberArn {record['subscriberArn']!r} != {sub_arn!r}"
    )
    assert record["targetArn"] == target_arn, f"record targetArn {record['targetArn']!r} != {target_arn!r}"
    assert record["errorCode"] == "RESOURCE_NOT_FOUND", (
        f"expected errorCode RESOURCE_NOT_FOUND for a deleted target queue, got {record['errorCode']!r}"
    )
    assert isinstance(record.get("errorMessage"), str) and record["errorMessage"], (
        f"expected a non-empty errorMessage describing the failure, got {record.get('errorMessage')!r}"
    )
    assert record["exhaustedRetryCondition"] == "MaximumRetryAttempts", (
        f"expected exhaustedRetryCondition MaximumRetryAttempts with MaxRetryAttempts=0, "
        f"got {record['exhaustedRetryCondition']!r}"
    )
    assert record["retryAttempts"] == 0, f"expected retryAttempts 0, got {record['retryAttempts']!r}"
    assert record["failedMessages"][0]["eventId"] == event_id, (
        f"record's failedMessages eventId {record['failedMessages'][0]['eventId']!r} != {event_id!r}"
    )

    for key in ("source", "detail-type", "detail", "account"):
        assert key not in record, (
            f"the dead-letter record must describe the failure, not replay the event; "
            f"found original-event key {key!r} in {record!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
