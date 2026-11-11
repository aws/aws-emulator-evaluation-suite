"""subscriber-put-events-delivers-to-sqs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscriber-put-events-delivers-to-sqs"
GROUP = "subscriber-delivery"
SERVICES = ["eventbridgev2"]

_ACTIVE_TIMEOUT_S = 60.0
_DELIVERY_TIMEOUT_S = 180.0
_REPUBLISH_INTERVAL_S = 10.0


def _teardown_bus(ebv2, bus_arn: str):
    """Delete the bus, waiting out a transient CREATING/DELETING rather than hiding it."""

    def run_undo() -> None:
        deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
        while True:
            try:
                ebv2.delete_event_bus(EventBusArn=bus_arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("InvalidStateException", "ResourceInUseException"):
                    raise
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)

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


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-ebv2-q-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn}]})})
    return url, arn


def _create_role(ctx, queue_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-ebv2-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="send-to-queue", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="send-to-queue"))
    return arn


def _publish_until_delivered(ebv2, sqs, bus_arn: str, source: str, queue_url: str, marker: str) -> dict:
    """Republish the marked entry until it is seen on the queue.

    The delivered envelope's own ``id`` is not the PutEvents ``EventId`` (a bus-minted delivery
    id, distinct from the publish-time one), so the marker in ``detail`` is what identifies it.
    """
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_put = 0.0
    attempts = 0
    while time.monotonic() < deadline:
        if time.monotonic() >= next_put:
            put = ebv2.put_events(EventBusArn=bus_arn, Entries=[{
                "Source": source, "DetailType": "sim2real-ebv2-delivery",
                "Detail": json.dumps({"marker": marker}),
            }])
            assert put["FailedEntryCount"] == 0, f"PutEvents failed: {put['Entries']!r}"
            attempts += 1
            next_put = time.monotonic() + _REPUBLISH_INTERVAL_S
        for msg in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if isinstance(body.get("detail"), dict) and body["detail"].get("marker") == marker:
                return body
    raise AssertionError(
        f"no PutEvents entry reached the SQS target within {_DELIVERY_TIMEOUT_S}s ({attempts} "
        f"publish attempt(s))"
    )


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A subscriber with an SQS target delivers a PutEvents entry as the classic EventBridge
    envelope, with its Source, DetailType, Detail and account intact.
    """
    ebv2 = ctx.client("eventbridgev2")
    sqs = ctx.client("sqs")

    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")
    sub_name = ctx.unique_name("sim2real-behav-ebv2-sub-")
    source = ctx.unique_name("sim2real.ebv2.")

    bus = ebv2.create_event_bus(Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_bus_active(ebv2, bus_arn)

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_role(ctx, queue_arn)

    sub = ebv2.create_subscriber(
        Name=sub_name, EventBusArn=bus_arn, ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        InvokeConfiguration={"RoleArn": role_arn, "TargetArn": queue_arn, "SqsParameters": {}},
    )
    sub_arn = sub["SubscriberArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ebv2.delete_subscriber(SubscriberArn=sub_arn)))
    assert sub["State"] == "RUNNING", f"expected a fresh subscriber to be RUNNING, got {sub['State']!r}"

    marker = ctx.unique_name("marker-")
    envelope = _publish_until_delivered(ebv2, sqs, bus_arn, source, queue_url, marker)

    assert envelope["source"] == source, f"delivered source {envelope['source']!r} != {source!r}"
    assert envelope["detail-type"] == "sim2real-ebv2-delivery", (
        f"delivered detail-type {envelope['detail-type']!r}, expected 'sim2real-ebv2-delivery'"
    )
    assert envelope["detail"] == {"marker": marker}, (
        f"delivered detail {envelope['detail']!r} != {{'marker': {marker!r}}}"
    )
    assert envelope["account"] == ctx.account, (
        f"delivered account {envelope['account']!r} != {ctx.account!r}"
    )


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
