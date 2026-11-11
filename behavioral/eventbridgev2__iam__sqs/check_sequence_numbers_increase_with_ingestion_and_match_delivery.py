"""sequence-numbers-increase-with-ingestion-and-match-delivery."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sequence-numbers-increase-with-ingestion-and-match-delivery"
GROUP = "event-ordering"
SERVICES = ["eventbridgev2", "iam", "sqs"]

_SETTLE_TIMEOUT_S = 60.0
_WARMUP_TIMEOUT_S = 180.0
_WARMUP_INTERVAL_S = 5.0
_DELIVERY_TIMEOUT_S = 120.0
_WARM = "sim2real-warmup"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _bus_teardown(ebv2, bus_arn: str):
    """Delete the bus, waiting out a transient state or a child whose delete is still settling."""

    def run_undo() -> None:
        deadline = time.monotonic() + _SETTLE_TIMEOUT_S
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


def _wait_bus_state(ctx, ebv2, bus_arn: str, state: str) -> dict:
    """DescribeEventBus once the bus reports ``state``."""
    deadline = time.monotonic() + _budget_s(ctx, _SETTLE_TIMEOUT_S)
    while True:
        described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        if described["State"] == state:
            return described
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the run budget ended before the bus settled; not graded")
            raise AssertionError(f"bus stayed {described['State']!r}, never reached {state}")
        time.sleep(2)


def _create_bus(ctx, ebv2, **kwargs) -> dict:
    """An ACTIVE bus of the check's own, deleted at cleanup."""
    bus = ebv2.create_event_bus(
        Name=kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-ebv2-bus-"),
        ClientToken=ctx.unique_name("sim2real-behav-tok-"),
        **kwargs,
    )
    ctx.on_cleanup(_bus_teardown(ebv2, bus["EventBusArn"]))
    _wait_bus_state(ctx, ebv2, bus["EventBusArn"], "ACTIVE")
    return bus


def _create_subscriber(ctx, ebv2, bus_arn: str, invoke: dict, **kwargs) -> dict:
    """A subscriber on ``bus_arn``, deleted at cleanup."""
    sub = ebv2.create_subscriber(
        Name=kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-ebv2-sub-"),
        EventBusArn=bus_arn,
        ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        InvokeConfiguration=invoke,
        **kwargs,
    )
    _track_subscriber(ctx, ebv2, sub)
    return sub


def _track_subscriber(ctx, ebv2, sub: dict) -> None:
    arn = sub["SubscriberArn"]
    ctx.on_cleanup(_teardown(lambda: ebv2.delete_subscriber(SubscriberArn=arn),
                             "ResourceNotFoundException"))


def _create_queue(ctx, label: str, fifo: bool = False) -> tuple[str, str]:
    """(QueueUrl, QueueArn) of a queue that admits deliveries from EventBridge."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-behav-ebv2-{label}-") + (".fifo" if fifo else "")
    url = sqs.create_queue(QueueName=name, Attributes={"FifoQueue": "true"} if fifo else {},
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn}]})})
    return url, arn


def _create_role(ctx, resources: list[str], actions: list[str]) -> str:
    """A delivery role EventBridge assumes, allowed ``actions`` on ``resources``."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-ebv2-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="deliver", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": actions, "Resource": resources}]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="deliver"),
                             "NoSuchEntity"))
    return arn


def _is_warm(body: str) -> bool:
    """True for a warm-up delivery, which no assertion grades."""
    if _WARM in body:
        return True
    for part in body.split(":"):
        try:
            if _WARM.encode() in base64.b64decode(part, validate=True):
                return True
        except ValueError:
            continue
    return False


def _receive(sqs, url: str) -> list[str]:
    """The bodies one receive returns, each deleted."""
    messages = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=2).get("Messages", [])
    for message in messages:
        sqs.delete_message(QueueUrl=url, ReceiptHandle=message["ReceiptHandle"])
    return [message["Body"] for message in messages]


def _drain(sqs, url: str) -> list[str]:
    """The bodies one receive returns, each deleted, less warm-up deliveries."""
    return [body for body in _receive(sqs, url) if not _is_warm(body)]


def _collect(ctx, sqs, url: str, done, what: str) -> list[str]:
    """Every body received on ``url`` until ``done(bodies)`` holds."""
    deadline = time.monotonic() + _budget_s(ctx, _DELIVERY_TIMEOUT_S)
    bodies: list[str] = []
    while True:
        bodies.extend(_drain(sqs, url))
        if done(bodies):
            return bodies
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended before {what}; not graded")
            raise AssertionError(f"{what} did not happen within {_DELIVERY_TIMEOUT_S}s; "
                                 f"received {bodies!r}")


def _warm_up(ctx, publish, sqs, urls: list[str]) -> None:
    """Republish a warm-up event until one reaches every queue.

    A new subscriber starts consuming shortly after CreateSubscriber returns, and a new role
    needs IAM propagation, so a test event is published only once each path has delivered.
    """
    deadline = time.monotonic() + _budget_s(ctx, _WARMUP_TIMEOUT_S)
    pending = set(urls)
    next_put = 0.0
    while pending:
        if time.monotonic() >= next_put:
            publish(ctx.unique_name(_WARM + "-"))
            next_put = time.monotonic() + _WARMUP_INTERVAL_S
        for url in sorted(pending):
            if any(_is_warm(body) for body in _receive(sqs, url)):
                pending.discard(url)
        if pending and time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the run budget ended during warm-up; not graded")
            raise AssertionError(f"no warm-up event reached {len(pending)} queue(s) in "
                                 f"{_WARMUP_TIMEOUT_S}s")


def _put_events_warm(ebv2, bus_arn: str, **detail):
    """A warm-up publisher sending one PutEvents entry carrying the marker and ``detail``."""

    def publish(marker: str) -> None:
        put = ebv2.put_events(EventBusArn=bus_arn, Entries=[{
            "Source": "sim2real.ebv2.check", "DetailType": "sim2real-warm-up",
            "Detail": json.dumps({"marker": marker, **detail})}])
        assert put["FailedEntryCount"] == 0, f"warm-up PutEvents failed: {put['Entries']!r}"

    return publish


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents calls made one after another return increasing SequenceNumbers, and each delivered
    event carries the aws:SequenceNumber and aws:EventId its publish call returned.
    
    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-custom-bus-addressing.html
    """
    ebv2 = ctx.client("eventbridgev2")
    sqs = ctx.client("sqs")
    bus_arn = _create_bus(ctx, ebv2)["EventBusArn"]
    ordered_url, ordered_arn = _create_queue(ctx, "ordered")
    role_arn = _create_role(ctx, [ordered_arn], ["sqs:SendMessage"])

    def put(marker, **detail):
        put = ebv2.put_events(EventBusArn=bus_arn, Entries=[{
            "Source": "sim2real.ebv2.check", "DetailType": "sim2real-check",
            "Detail": json.dumps({"marker": marker, **detail})}])
        assert put["FailedEntryCount"] == 0, f"PutEvents failed: {put['Entries']!r}"
        return put["Entries"][0]

    def marker_of(body):
        try:
            event = json.loads(body)
        except ValueError:
            return None
        detail = event.get("detail") if isinstance(event, dict) else None
        return detail.get("marker") if isinstance(detail, dict) else None

    _create_subscriber(ctx, ebv2, bus_arn, {"RoleArn": role_arn, "TargetArn": ordered_arn, "SqsParameters": {}},
                       Transformer={"Type": "WITH_METADATA"})
    _warm_up(ctx, _put_events_warm(ebv2, bus_arn), sqs, [ordered_url])
    published = {}
    order = []
    for i in range(3):
        marker = ctx.unique_name(f"m-seq-{i}-")
        published[marker] = put(marker)
        order.append(marker)
    numbers = [int(published[m]["SequenceNumber"]) for m in order]
    assert numbers == sorted(numbers) and len(set(numbers)) == 3, (
        f"sequential PutEvents calls returned SequenceNumbers {numbers!r}, expected strictly increasing"
    )

    def delivered(bodies):
        found = {}
        for body in bodies:
            event = json.loads(body)
            marker = event["Data"].get("detail", {}).get("marker")
            if marker in published:
                found[marker] = event["SystemMetadata"]
        return found

    seen = delivered(_collect(ctx, sqs, ordered_url, lambda b: len(delivered(b)) == 3,
                              "delivery of all three events"))
    for marker in order:
        assert seen[marker]["aws:SequenceNumber"] == published[marker]["SequenceNumber"], (
            f"delivered aws:SequenceNumber {seen[marker].get('aws:SequenceNumber')!r} != "
            f"{published[marker]['SequenceNumber']!r}"
        )
        assert seen[marker]["aws:EventId"] == published[marker]["EventId"], (
            f"delivered aws:EventId {seen[marker].get('aws:EventId')!r} != {published[marker]['EventId']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
