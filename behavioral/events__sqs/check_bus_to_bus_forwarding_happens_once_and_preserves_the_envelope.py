"""bus-to-bus-forwarding-happens-once-and-preserves-the-envelope."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# EventBridge forwards an event between same-Region buses at most once, and the forwarded event is
# identical to the original:
# https://aws.amazon.com/blogs/compute/using-bus-to-bus-event-routing-with-amazon-eventbridge/

CHECK = "bus-to-bus-forwarding-happens-once-and-preserves-the-envelope"
GROUP = "event-propagation"
SERVICES = ["events", "sqs"]

_MIN_ABSENCE_WINDOW_S = 45.0
_LIVENESS_TIMEOUT_S = 120.0
_DELIVERY_TIMEOUT_S = 90.0
# Fields that differ between any two events by construction and are therefore excluded from the
# forwarded-versus-direct envelope comparison.
_PER_EVENT_FIELDS = ("id", "time", "detail")


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A→B forwarding delivers an untouched envelope to B's target, and B does not forward it on to C
    even though B→C forwarding demonstrably works."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    source = _xname(ctx, "src")

    bus_a, arn_a = _create_bus(ctx)
    bus_b, arn_b = _create_bus(ctx)
    bus_c, arn_c = _create_bus(ctx)

    role_arn = _create_events_role(ctx, put_events_on=[arn_b, arn_c])

    queue_b = _create_queue(ctx)
    queue_c = _create_queue(ctx)

    pattern = {"source": [source]}
    resources = [f"arn:aws:events:{ctx.region}:{account}:event-bus/{bus_a}"]
    # A -> B, and B -> C: the two forwarding hops.
    _put_rule(ctx, bus_a, pattern, {"Id": "t1", "Arn": arn_b, "RoleArn": role_arn})
    _put_rule(ctx, bus_b, pattern, {"Id": "t1", "Arn": arn_c, "RoleArn": role_arn})
    # The two observation points, one per bus.
    rule_bq = _put_rule(ctx, bus_b, pattern, {"Id": "t1", "Arn": queue_b["arn"]})
    rule_cq = _put_rule(ctx, bus_c, pattern, {"Id": "t1", "Arn": queue_c["arn"]})
    _set_queue_policy(ctx, queue_b, "events.amazonaws.com", rule_bq["arn"])
    _set_queue_policy(ctx, queue_c, "events.amazonaws.com", rule_cq["arn"])

    # --- twin control, leg 1: B -> C -> queue_c really works, measured on this exact wiring. ---
    direct_marker, direct_on_c, latency_bc = _emit_until_delivered(
        ctx, bus_b, source, "Direct", queue_c["url"], timeout_s=_LIVENESS_TIMEOUT_S
    )
    assert direct_on_c["detail"]["marker"] == direct_marker, (
        f"the B->C control event must arrive on queue_c carrying its own marker, got "
        f"{direct_on_c!r}"
    )

    # --- twin control, leg 2: A -> B -> queue_b really works, measured on this exact wiring. ---
    _, _, latency_ab = _emit_until_delivered(
        ctx, bus_a, source, "Warmup", queue_b["url"], timeout_s=_LIVENESS_TIMEOUT_S
    )

    # Both hops are now live. Clear both queues before establishing the reference envelope.
    _drain(ctx, queue_b["url"], window_s=5.0)
    _drain(ctx, queue_c["url"], window_s=5.0)

    # --- the reference envelope: put DIRECTLY on bus B (never forwarded), with the SAME
    # detail-type and resources the measured event below will carry. The twin controls above use
    # their own detail-types ("Direct"/"Warmup") and empty Resources to prove liveness, so their
    # copies are not fit to serve as the reference for the field-by-field comparison: comparing
    # against them would flag detail-type/resources as "rewritten by forwarding" when they were
    # simply given different literals at PutEvents time. This reference isolates what forwarding
    # itself does.
    reference_marker = uuid.uuid4().hex
    ref_resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "Forwarded",
                "Detail": json.dumps({"marker": reference_marker, "nested": {"n": 7, "flag": True}}),
                "Resources": list(resources),
                "EventBusName": bus_b,
            }
        ]
    )
    assert ref_resp.get("FailedEntryCount") == 0, (
        f"the reference PutEvents on bus {bus_b} must be accepted, got {ref_resp!r}"
    )
    direct_on_b = _await_marker(ctx, queue_b["url"], reference_marker, timeout_s=_DELIVERY_TIMEOUT_S)[0]

    # Clear both queues again so the measured event is the only thing in flight.
    _drain(ctx, queue_b["url"], window_s=5.0)
    _drain(ctx, queue_c["url"], window_s=5.0)

    # --- the measured event: emitted ONCE on A. ---
    marker = uuid.uuid4().hex
    detail = {"marker": marker, "nested": {"n": 7, "flag": True}}
    resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "Forwarded",
                "Detail": json.dumps(detail),
                "Resources": list(resources),
                "EventBusName": bus_a,
            }
        ]
    )
    assert resp.get("FailedEntryCount") == 0, (
        f"the measured PutEvents on bus {bus_a} must be accepted, got {resp!r}"
    )

    # --- first hop: the forwarded envelope arrives at the CONSUMER, and is untouched. ---
    forwarded, _ = _await_marker(ctx, queue_b["url"], marker, timeout_s=_DELIVERY_TIMEOUT_S)
    assert forwarded["source"] == source, (
        f"the forwarded event must keep its source: expected {source!r}, got {forwarded.get('source')!r}"
    )
    assert forwarded["detail-type"] == "Forwarded", (
        f"the forwarded event must keep its detail-type: expected 'Forwarded', got "
        f"{forwarded.get('detail-type')!r}"
    )
    assert forwarded["detail"] == detail, (
        f"the forwarded event must keep its detail byte-for-byte: expected {detail}, got "
        f"{forwarded.get('detail')!r}"
    )
    assert forwarded.get("resources") == resources, (
        f"the forwarded event must keep its resources array: expected {resources}, got "
        f"{forwarded.get('resources')!r}"
    )
    assert forwarded.get("account") == account, (
        f"the forwarded event must keep the originating account: expected {account!r}, got "
        f"{forwarded.get('account')!r}"
    )
    assert forwarded.get("region") == ctx.region, (
        f"the forwarded event must keep the originating region: expected {ctx.region!r}, got "
        f"{forwarded.get('region')!r}"
    )
    assert "replay-name" not in forwarded, (
        f"a forwarded event is not a replayed event and must not carry replay-name: {forwarded!r}"
    )
    # Structurally: forwarding adds and removes nothing relative to a direct delivery.
    assert sorted(forwarded) == sorted(direct_on_b), (
        f"forwarding must not add or remove envelope fields: forwarded keys "
        f"{sorted(forwarded)} vs directly-delivered keys {sorted(direct_on_b)}"
    )
    differing = {
        k: (direct_on_b.get(k), forwarded.get(k))
        for k in forwarded
        if k not in _PER_EVENT_FIELDS and direct_on_b.get(k) != forwarded.get(k)
    }
    assert differing == {}, (
        f"forwarding must not rewrite any envelope field: (direct, forwarded) pairs that differ were "
        f"{json.dumps(differing, default=str)[:300]}"
    )

    # --- second hop must NOT happen, bounded by the two measured latencies. ---
    window = max(_MIN_ABSENCE_WINDOW_S, 3.0 * (latency_ab + latency_bc))
    leaked = [
        body
        for body in _drain(ctx, queue_c["url"], window_s=window)
        if isinstance(body, dict) and (body.get("detail") or {}).get("marker") == marker
    ]
    assert leaked == [], (
        f"bus {bus_c} received an event that had ALREADY been forwarded once (A->B): EventBridge "
        f"forwards between same-Region buses at most once, so this is a second hop that must not "
        f"exist. Window was {window:.0f}s = 3x(A->B {latency_ab:.1f}s + B->C {latency_bc:.1f}s). "
        f"Leaked: {json.dumps(leaked, default=str)[:300]}"
    )
    depth = sqs.get_queue_attributes(
        QueueUrl=queue_c["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert depth == "0", (
        f"second observable disagrees with the empty drain: "
        f"ApproximateNumberOfMessages on the bus-{bus_c} queue is {depth!r}, expected '0'"
    )

    # --- and the B->C hop is STILL live at the end, so the silence above was about the hop limit
    # rather than about C having quietly died mid-run. ---
    recheck_marker, recheck_body, _ = _emit_until_delivered(
        ctx, bus_b, source, "Recheck", queue_c["url"], timeout_s=_LIVENESS_TIMEOUT_S
    )
    assert (recheck_body.get("detail") or {}).get("marker") == recheck_marker, (
        f"the B->C wiring must still deliver after the absence window, got {recheck_body!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tolerate(fn, *tolerated: str, leak: str = "") -> None:
    """Run a teardown call. With a leak label, an error code outside `tolerated` is reported as a
    leak; without one, a refused teardown call is ignored."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if leak and code not in tolerated:
            raise RuntimeError(f"{leak}: {code}") from exc


def _create_bus(ctx) -> tuple[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "bus")
    arn = events.create_event_bus(Name=name, Tags=_xsvc_tags_kv())["EventBusArn"]

    def _teardown(n=name):
        _tolerate(lambda: ctx.client("events").delete_event_bus(Name=n), "ResourceNotFoundException", leak=f"could not delete event bus {n}")

    ctx.on_cleanup(_teardown)
    return name, arn


def _create_events_role(ctx, *, put_events_on: list[str]) -> str:
    """An IAM role EventBridge can assume, allowed to PutEvents on the given buses."""
    iam = ctx.client("iam")
    name = _xname(ctx, "role")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda n=name: _delete_role(ctx, n))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="put-events",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "events:PutEvents", "Resource": put_events_on}
                ],
            }
        ),
    )
    return arn


def _delete_role(ctx, name: str) -> None:
    """An IAM role needs every inline and attached policy removed before it can be deleted."""
    iam = ctx.client("iam")
    try:
        for policy in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=policy)
        for attached in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=attached["PolicyArn"])
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise RuntimeError(f"could not delete role {name}: {exc}") from exc


def _create_queue(ctx) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _set_queue_policy(ctx, queue: dict, service: str, source_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowServiceSend",
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": source_arn}},
            }
        ],
    }
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )


def _put_rule(ctx, bus: str, pattern: dict, target: dict) -> dict[str, str]:
    """A rule on `bus` for `pattern` with exactly one target. Registers teardown. Returns {name,arn}."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    arn = events.put_rule(
        Name=name, EventBusName=bus, EventPattern=json.dumps(pattern), Tags=_xsvc_tags_kv()
    )["RuleArn"]

    def _teardown(n=name, b=bus, tid=target["Id"]):
        ev = ctx.client("events")
        _tolerate(lambda: ev.remove_targets(Rule=n, EventBusName=b, Ids=[tid]), "ResourceNotFoundException", leak=f"could not remove target {tid} from rule {n} on {b}")
        _tolerate(lambda: ev.delete_rule(Name=n, EventBusName=b, Force=True), "ResourceNotFoundException", leak=f"could not delete rule {n} on bus {b}")

    ctx.on_cleanup(_teardown)
    events.put_targets(Rule=name, EventBusName=bus, Targets=[target])
    return {"name": name, "arn": arn}


def _body(msg: dict):
    """Parse an SQS message body as JSON, falling back to the raw string."""
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _drain(ctx, queue_url: str, *, window_s: float, max_total: int = 25) -> list:
    """Long-poll a queue for `window_s` and return every parsed body seen, deleting as it goes.

    This is the NEGATIVE observable. An empty return only means something because the callers above
    have already proved both hops live on this exact wiring — used alone it would pass against a
    target that delivers nothing at all.
    """
    sqs = ctx.client("sqs")
    seen: list = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            seen.append(_body(msg))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _await_marker(ctx, queue_url: str, marker: str, *, timeout_s: float) -> tuple[dict, float]:
    """Poll until a message whose detail.marker == marker arrives. RAISES on timeout.

    Returns (parsed body, seconds waited).
    """
    started = time.monotonic()
    others: list = []
    deadline = started + timeout_s
    while time.monotonic() < deadline:
        for body in _drain(ctx, queue_url, window_s=min(8.0, max(1.0, deadline - time.monotonic()))):
            if isinstance(body, dict) and (body.get("detail") or {}).get("marker") == marker:
                return body, time.monotonic() - started
            others.append(body)
    raise AssertionError(
        f"no message carrying detail.marker={marker!r} arrived on {queue_url} within {timeout_s}s "
        f"(other bodies seen meanwhile: {json.dumps(others, default=str)[:200]})"
    )


def _emit_until_delivered(
    ctx, bus: str, source: str, detail_type: str, queue_url: str, *, timeout_s: float
) -> tuple[str, dict, float]:
    """PutEvents on `bus` with a FRESH marker until one of them reaches `queue_url`. RAISES on timeout.

    Re-emitting is required, not optional: a freshly created rule silently drops events until the
    routing goes live, and EventBridge never retries a dropped event. A fresh marker per attempt
    means the returned latency is the latency of the attempt that actually landed, not of the first
    one. Returns (marker, parsed body, seconds from that emission to arrival).
    """
    events = ctx.client("events")
    deadline = time.monotonic() + timeout_s
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        marker = uuid.uuid4().hex
        sent_at = time.monotonic()
        resp = events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": detail_type,
                    "Detail": json.dumps({"marker": marker, "nested": {"n": 7, "flag": True}}),
                    "Resources": [],
                    "EventBusName": bus,
                }
            ]
        )
        assert resp.get("FailedEntryCount") == 0, (
            f"PutEvents on bus {bus} must be accepted while establishing liveness, got {resp!r}"
        )
        for body in _drain(ctx, queue_url, window_s=8.0):
            if isinstance(body, dict) and (body.get("detail") or {}).get("marker") == marker:
                return marker, body, max(time.monotonic() - sent_at, 0.001)
    raise AssertionError(
        f"the {detail_type} control event never reached {queue_url} from bus {bus} after {attempts} "
        f"PutEvents attempts over {timeout_s}s — the positive leg could not be established, so the "
        f"absence assertion this control exists to license is unprovable"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
