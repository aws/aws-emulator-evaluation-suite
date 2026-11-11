"""put-events-content-based-deduplication-suppresses-resend."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-events-content-based-deduplication-suppresses-resend"
GROUP = "deduplication"
SERVICES = ["eventbridgev2", "iam", "sqs"]

_ACTIVE_TIMEOUT_S = 60.0
_DELIVERY_TIMEOUT_S = 120.0
_WARMUP_TIMEOUT_S = 180.0
_WARMUP_INTERVAL_S = 10.0


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


def _create_queue(ctx):
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


def _receive_matching(sqs, queue_url: str, *markers: str) -> list:
    """Delivered bodies whose ``detail.marker`` is one of ``markers``, one poll."""
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    seen = []
    for msg in resp.get("Messages", []):
        body = json.loads(msg["Body"])
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if isinstance(body.get("detail"), dict) and body["detail"].get("marker") in markers:
            seen.append(body)
    return seen


def _warm_up(ebv2, sqs, bus_arn: str, source: str, queue_url: str) -> None:
    """Republish a throwaway entry until delivered, past the subscriber's IAM propagation."""
    marker = f"warmup-{bus_arn[-12:]}"
    deadline = time.monotonic() + _WARMUP_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < deadline:
        if time.monotonic() >= next_put:
            ebv2.put_events(EventBusArn=bus_arn, Entries=[{
                "Source": source, "DetailType": "sim2real-ebv2-warmup",
                "Detail": json.dumps({"marker": marker}),
            }])
            next_put = time.monotonic() + _WARMUP_INTERVAL_S
        if _receive_matching(sqs, queue_url, marker):
            return
    raise AssertionError(f"no warm-up entry reached the SQS target within {_WARMUP_TIMEOUT_S}s")


def _collect_until_seen(observe, markers: set[str], *, budget_s: float) -> list:
    """Every body ``observe()`` returns until each of ``markers`` has been delivered."""
    deadline = time.monotonic() + budget_s
    seen: list = []
    while True:
        seen.extend(observe())
        if markers <= {b["detail"]["marker"] for b in seen}:
            return seen
        if time.monotonic() > deadline:
            raise AssertionError(
                f"not every one of {sorted(markers)} was delivered in {budget_s}s; saw {seen!r}"
            )


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A PutEvents entry republished with the same content under CONTENT_BASED deduplication is
    reported DEDUPLICATED; the original entry and a distinct control entry both reach the target
    queue."""
    ebv2 = ctx.client("eventbridgev2")
    sqs = ctx.client("sqs")

    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")
    sub_name = ctx.unique_name("sim2real-behav-ebv2-sub-")
    source = ctx.unique_name("sim2real.ebv2.")
    marker = ctx.unique_name("marker-")

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

    _warm_up(ebv2, sqs, bus_arn, source, queue_url)

    # A fixed Time keeps both PutEvents calls byte-identical, so the hash is the same.
    fixed_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
    entry = {
        "Source": source, "DetailType": "sim2real-ebv2-dedup",
        "Detail": json.dumps({"marker": marker}), "Time": fixed_time,
    }
    dedup_cfg = {"DeduplicationType": "CONTENT_BASED"}

    first = ebv2.put_events(EventBusArn=bus_arn, Entries=[entry], DeduplicationConfiguration=dedup_cfg)
    assert first["FailedEntryCount"] == 0, f"first PutEvents failed: {first['Entries']!r}"
    assert first["Entries"][0].get("SuccessCode") == "PUBLISHED", (
        f"first entry's SuccessCode was {first['Entries'][0].get('SuccessCode')!r}, expected 'PUBLISHED'"
    )

    second = ebv2.put_events(EventBusArn=bus_arn, Entries=[entry], DeduplicationConfiguration=dedup_cfg)
    assert second["FailedEntryCount"] == 0, f"second PutEvents failed: {second['Entries']!r}"
    assert second["Entries"][0].get("SuccessCode") == "DEDUPLICATED", (
        f"repeated entry's SuccessCode was {second['Entries'][0].get('SuccessCode')!r}, "
        f"expected 'DEDUPLICATED'"
    )

    # Positive control: a distinct entry is delivered alongside the original.
    control_marker = ctx.unique_name("control-")
    control = ebv2.put_events(EventBusArn=bus_arn, Entries=[{
        "Source": source, "DetailType": "sim2real-ebv2-dedup",
        "Detail": json.dumps({"marker": control_marker}),
    }])
    assert control["FailedEntryCount"] == 0, f"control PutEvents failed: {control['Entries']!r}"

    seen = _collect_until_seen(
        lambda: _receive_matching(sqs, queue_url, marker, control_marker),
        {marker, control_marker}, budget_s=_DELIVERY_TIMEOUT_S,
    )
    details = {b["detail"]["marker"]: b["detail"] for b in seen}
    assert details[marker] == {"marker": marker}, (
        f"delivered original detail {details[marker]!r} != {{'marker': {marker!r}}}"
    )
    assert details[control_marker] == {"marker": control_marker}, (
        f"delivered control detail {details[control_marker]!r} != {{'marker': {control_marker!r}}}"
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
