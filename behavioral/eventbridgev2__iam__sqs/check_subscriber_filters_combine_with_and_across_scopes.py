"""subscriber-filters-combine-with-and-across-scopes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscriber-filters-combine-with-and-across-scopes"
GROUP = "subscriber-filtering"
SERVICES = ["eventbridgev2", "iam", "sqs"]

_ACTIVE_TIMEOUT_S = 60.0
_WARMUP_TIMEOUT_S = 180.0
_WARMUP_INTERVAL_S = 10.0
_DELIVERY_TIMEOUT_S = 120.0


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


def _create_queue(ctx, suffix: str):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-behav-ebv2-q{suffix}-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn}]})})
    return url, arn


def _create_role(ctx, queue_arns: list[str]) -> str:
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
    iam.put_role_policy(RoleName=name, PolicyName="send-to-queues", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arns}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="send-to-queues"))
    return arn


def _raw_entry(kind: str, region: str, marker: str) -> dict:
    data = json.dumps({"detail": {"kind": kind}, "marker": marker}).encode()
    return {
        "Data": data,
        "Metadata": {"region": region},
        "SystemMetadata": {"ContentType": "application/json"},
    }


def _receive_markers(sqs, queue_url: str, known: set[str]) -> list[str]:
    """Delivered markers, among ``known``, seen in one poll.

    The delivered body for a raw-published event is the ``Data`` payload exactly as sent,
    so the marker sits at its top level, not nested under ``detail``.
    """
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    seen = []
    for msg in resp.get("Messages", []):
        body = json.loads(msg["Body"])
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        marker = body.get("marker")
        if marker in known:
            seen.append(marker)
    return seen


def _warm_up(ebv2, sqs, bus_arn: str, queue_url: str, kind: str, region: str) -> None:
    """Republish a throwaway event matching the target subscriber's own filter, past IAM
    propagation."""
    marker = f"warmup-{bus_arn[-12:]}-{queue_url[-12:]}"
    deadline = time.monotonic() + _WARMUP_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < deadline:
        if time.monotonic() >= next_put:
            ebv2.put_raw_events(EventBusArn=bus_arn, Entries=[_raw_entry(kind, region, marker)])
            next_put = time.monotonic() + _WARMUP_INTERVAL_S
        if _receive_markers(sqs, queue_url, {marker}):
            return
    raise AssertionError(f"no warm-up event reached the SQS target within {_WARMUP_TIMEOUT_S}s")


@tags("axis:negative-delivery", "cap:c5", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A subscriber's DATA and METADATA filters combine with AND: only an event matching
    both scopes reaches a subscriber that carries both, while one matching DATA alone
    still reaches a sibling subscriber whose filter names DATA only.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-custom-bus-filtering.html
    """
    ebv2 = ctx.client("eventbridgev2")
    sqs = ctx.client("sqs")

    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")
    bus = ebv2.create_event_bus(Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_bus_active(ebv2, bus_arn)

    data_url, data_arn = _create_queue(ctx, "data")
    both_url, both_arn = _create_queue(ctx, "both")
    role_arn = _create_role(ctx, [data_arn, both_arn])

    data_pattern = json.dumps({"detail": {"kind": ["a"]}})
    meta_pattern = json.dumps({"region": ["west"]})

    sub_data = ebv2.create_subscriber(
        Name=ctx.unique_name("sim2real-behav-ebv2-sub-data-"), EventBusArn=bus_arn,
        ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        InvokeConfiguration={"RoleArn": role_arn, "TargetArn": data_arn, "SqsParameters": {}},
        FilterConfiguration={"Filters": [{"Scope": "DATA", "Pattern": data_pattern}]},
    )
    data_sub_arn = sub_data["SubscriberArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: ebv2.delete_subscriber(SubscriberArn=data_sub_arn)
    ))
    assert sub_data["State"] == "RUNNING", f"expected RUNNING, got {sub_data['State']!r}"

    sub_both = ebv2.create_subscriber(
        Name=ctx.unique_name("sim2real-behav-ebv2-sub-both-"), EventBusArn=bus_arn,
        ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        InvokeConfiguration={"RoleArn": role_arn, "TargetArn": both_arn, "SqsParameters": {}},
        FilterConfiguration={"Filters": [
            {"Scope": "DATA", "Pattern": data_pattern},
            {"Scope": "METADATA", "Pattern": meta_pattern},
        ]},
    )
    both_sub_arn = sub_both["SubscriberArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: ebv2.delete_subscriber(SubscriberArn=both_sub_arn)
    ))
    assert sub_both["State"] == "RUNNING", f"expected RUNNING, got {sub_both['State']!r}"

    _warm_up(ebv2, sqs, bus_arn, data_url, "a", "irrelevant")
    _warm_up(ebv2, sqs, bus_arn, both_url, "a", "west")

    m_match_both = ctx.unique_name("m-both-")      # kind=a, region=west: matches both subscribers
    m_data_only = ctx.unique_name("m-data-only-")  # kind=a, region=east: DATA matches, METADATA does not
    m_no_data = ctx.unique_name("m-no-data-")       # kind=b, region=west: DATA does not match
    m_neither = ctx.unique_name("m-neither-")       # kind=b, region=east: neither scope matches
    all_markers = {m_match_both, m_data_only, m_no_data, m_neither}

    put = ebv2.put_raw_events(EventBusArn=bus_arn, Entries=[
        _raw_entry("a", "west", m_match_both),
        _raw_entry("a", "east", m_data_only),
        _raw_entry("b", "west", m_no_data),
        _raw_entry("b", "east", m_neither),
    ])
    assert put["FailedEntryCount"] == 0, f"PutRawEvents reported failures: {put['Entries']!r}"

    # Positive control, published after the four entries and matching both subscribers: once
    # it reaches a queue, a wrongly unfiltered entry has had its chance to arrive there too.
    m_control = ctx.unique_name("m-control-")
    all_markers.add(m_control)
    control = ebv2.put_raw_events(EventBusArn=bus_arn, Entries=[_raw_entry("a", "west", m_control)])
    assert control["FailedEntryCount"] == 0, f"control PutRawEvents failed: {control['Entries']!r}"

    def _poll_until(queue_url: str, expect: set[str], budget_s: float) -> set[str]:
        deadline = time.monotonic() + budget_s
        found: set[str] = set()
        while True:
            found.update(_receive_markers(sqs, queue_url, all_markers))
            if expect <= found:
                return found
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"{sorted(expect - found)} never reached {queue_url} in {budget_s}s; "
                    f"saw {sorted(found)}"
                )

    data_seen = _poll_until(data_url, {m_match_both, m_data_only, m_control}, _DELIVERY_TIMEOUT_S)
    both_seen = _poll_until(both_url, {m_match_both, m_control}, _DELIVERY_TIMEOUT_S)

    assert data_seen == {m_match_both, m_data_only, m_control}, (
        f"DATA-only subscriber's queue saw {sorted(data_seen)}, expected exactly the two "
        f"entries matching kind=a and the control"
    )
    assert both_seen == {m_match_both, m_control}, (
        f"DATA+METADATA subscriber's queue saw {sorted(both_seen)}, expected exactly the "
        f"one entry matching kind=a AND region=west and the control"
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
