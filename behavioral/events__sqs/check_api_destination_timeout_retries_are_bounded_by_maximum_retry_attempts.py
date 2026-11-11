"""api-destination-timeout-retries-are-bounded-by-maximum-retry-attempts."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Assertion messages cite these properties:
#   H1 EventBridge retries a timed-out API-destination request up to the target's
#      MaximumRetryAttempts before sending the event to the DLQ.
#      https://repost.aws/knowledge-center/eventbridge-api-destination-target-failure
#   H2 Each attempt costs at least the 5 s client execution timeout and backoff only adds to it,
#      so _RETRIES extra attempts cost at least _RETRIES * 5 s more than the zero-retry twin.
#   H3 The DLQ ERROR_CODE for a timed-out invocation is undocumented, so it is asserted only as
#      non-empty and identical across the two rules.
#   H4 A dead-lettered event is terminal: exactly one DLQ message per rule per event.

CHECK = "api-destination-timeout-retries-are-bounded-by-maximum-retry-attempts"
GROUP = "event-propagation"
SERVICES = ["events", "sqs"]

_RETRIES = 3
_ENDPOINT_TIMEOUT_S = 5.0  # documented EventBridge client execution timeout per API-destination call
_MAX_EVENT_AGE_S = 86400  # the documented maximum, so event AGE never terminates either twin
_AUTHORIZED_TIMEOUT_S = 120.0
_ACTIVE_TIMEOUT_S = 90.0
_LIVENESS_TIMEOUT_S = 150.0
_RETRY_DLQ_TIMEOUT_S = 150.0
_EXTRA_COUNT_WINDOW_S = 20.0
# How promptly a zero-retry event must reach the DLQ for the retry separation to mean anything.
_PROMPT_DLQ_S = 180.0
# RFC 5737 TEST-NET-1: routed nowhere, so the TCP connect hangs into EventBridge's own timeout
# rather than failing fast as a DNS error would. Nothing outside this account is contacted.
_UNROUTABLE_ENDPOINT = "https://192.0.2.1/sim2real-hook"


# timing:real-time — lease: 5 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html
@tags(
    "axis:negative-delivery",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Twin API-destination rules differing only in MaximumRetryAttempts dead-letter the same event,
    the retrying twin at least one 5 s endpoint timeout later per extra retry (a lower bound, since
    backoff with jitter only adds), each DLQ message naming its own rule.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    source = _xname(ctx, "src")

    bus, _ = _create_bus(ctx)

    conn_name = ctx.unique_name("sim2real-xsvc-conn-")
    conn_arn = events.create_connection(
        Name=conn_name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "sim2real-not-a-secret"}
        },
    )["ConnectionArn"]
    ctx.on_cleanup(lambda n=conn_name: _delete_connection(ctx, n))
    authorized = _poll_until(
        lambda: events.describe_connection(Name=conn_name),
        lambda d: d["ConnectionState"] in ("AUTHORIZED", "CREATE_FAILED"),
        timeout_s=_AUTHORIZED_TIMEOUT_S,
        interval_s=2.0,
        description=f"connection {conn_name} leaves CREATING",
    )
    assert authorized["ConnectionState"] == "AUTHORIZED", (
        f"the connection must reach AUTHORIZED before the destination can be invoked, got "
        f"{authorized['ConnectionState']!r} StateReason={authorized.get('StateReason')!r}"
    )

    dest_name = ctx.unique_name("sim2real-xsvc-apidest-")
    dest_arn = events.create_api_destination(
        Name=dest_name,
        ConnectionArn=conn_arn,
        InvocationEndpoint=_UNROUTABLE_ENDPOINT,
        HttpMethod="POST",
        InvocationRateLimitPerSecond=300,
    )["ApiDestinationArn"]
    ctx.on_cleanup(lambda n=dest_name: _delete_api_destination(ctx, n))
    dest_state = _poll_until(
        lambda: events.describe_api_destination(Name=dest_name),
        lambda d: d["ApiDestinationState"] in ("ACTIVE", "INACTIVE"),
        timeout_s=_ACTIVE_TIMEOUT_S,
        interval_s=2.0,
        description=f"api destination {dest_name} settles",
    )
    assert dest_state["ApiDestinationState"] == "ACTIVE", (
        f"the api destination must be ACTIVE for EventBridge to attempt it, got "
        f"{dest_state['ApiDestinationState']!r}"
    )

    role_arn = _create_events_role(ctx, invoke_api_destination=dest_arn)

    dlq_zero = _create_queue(ctx)
    dlq_retry = _create_queue(ctx)
    pattern = {"source": [source]}

    rule_zero = _put_rule_with_api_destination(
        ctx, bus, pattern, dest_arn, role_arn, dlq_zero, retries=0
    )
    rule_retry = _put_rule_with_api_destination(
        ctx, bus, pattern, dest_arn, role_arn, dlq_retry, retries=_RETRIES
    )

    # --- both twins live, and the measured marker, in one loop: emit a fresh marker until the
    # ZERO-retry rule dead-letters it, which is the earliest possible signal that the wiring works.
    marker, zero_capture, sent_at = _emit_until_dead_lettered(ctx, bus, source, dlq_zero["url"])
    elapsed_zero = zero_capture["at"] - sent_at
    zero_dupes = _collect_marker(ctx, dlq_zero["url"], marker, timeout_s=_EXTRA_COUNT_WINDOW_S)
    assert zero_dupes == [], (
        f"the zero-retry DLQ received {len(zero_dupes) + 1} copies of marker {marker} — an event that "
        f"has been dead-lettered is terminal and must arrive exactly once (H4)"
    )
    assert elapsed_zero <= _PROMPT_DLQ_S, (
        f"with MaximumRetryAttempts=0 the event must reach the DLQ promptly: took {elapsed_zero:.1f}s, "
        f"expected no more than {_PROMPT_DLQ_S}s; a slow zero-retry leg would make the separation "
        f"assertion below meaningless"
    )

    # --- the twin: the SAME event, on the SAME destination, with _RETRIES extra attempts. ---
    retry_capture, _, retry_at = _await_marker(
        ctx, dlq_retry["url"], marker, timeout_s=_RETRY_DLQ_TIMEOUT_S
    )
    elapsed_retry = retry_at - sent_at
    retry_dupes = _collect_marker(ctx, dlq_retry["url"], marker, timeout_s=_EXTRA_COUNT_WINDOW_S)
    assert retry_dupes == [], (
        f"the {_RETRIES}-retry DLQ received {len(retry_dupes) + 1} copies of marker {marker} — one "
        f"dead-lettered event must produce exactly one DLQ message (H4)"
    )

    # --- the measurement: _RETRIES extra attempts cost at least _RETRIES endpoint timeouts. ---
    floor = _RETRIES * _ENDPOINT_TIMEOUT_S
    assert elapsed_retry - elapsed_zero >= floor, (
        f"MaximumRetryAttempts={_RETRIES} did not cost any measurable extra time: the same event "
        f"reached the zero-retry DLQ after {elapsed_zero:.1f}s and the {_RETRIES}-retry DLQ after "
        f"{elapsed_retry:.1f}s, a separation of {elapsed_retry - elapsed_zero:.1f}s where at least "
        f"{floor:.0f}s ({_RETRIES} x the documented {_ENDPOINT_TIMEOUT_S}s endpoint timeout) is "
        f"required. A target that ignores RetryPolicy dead-letters both at the same moment (H1, H2)"
    )

    # --- both DLQ envelopes are the original event, tagged with their OWN rule. ---
    for label, captured, rule in (
        ("zero-retry", zero_capture, rule_zero),
        (f"{_RETRIES}-retry", retry_capture, rule_retry),
    ):
        body = captured["body"]
        attrs = captured["attrs"]
        assert isinstance(body, dict), (
            f"the {label} DLQ body must be a JSON event envelope, got {body!r}"
        )
        assert (body.get("detail") or {}).get("marker") == marker, (
            f"the {label} DLQ body must be the original event: expected detail.marker={marker!r}, got "
            f"{json.dumps(body, default=str)[:200]}"
        )
        assert body.get("source") == source, (
            f"the {label} DLQ body must keep the original source {source!r}, got {body.get('source')!r}"
        )
        assert attrs.get("RULE_ARN", {}).get("StringValue") == rule["arn"], (
            f"the {label} DLQ message must name its OWN rule: expected RULE_ARN={rule['arn']!r}, got "
            f"{attrs.get('RULE_ARN')!r} — without this the two arrivals cannot be attributed to the "
            f"two different retry policies"
        )
        assert attrs.get("TARGET_ARN", {}).get("StringValue") == dest_arn, (
            f"the {label} DLQ message must name the api destination as the target: expected "
            f"{dest_arn!r}, got {attrs.get('TARGET_ARN')!r}"
        )
        assert (attrs.get("ERROR_CODE", {}).get("StringValue") or "") != "", (
            f"the {label} DLQ message must carry a non-empty ERROR_CODE; attributes were {attrs!r} (H3)"
        )

    zero_code = zero_capture["attrs"].get("ERROR_CODE", {}).get("StringValue")
    retry_code = retry_capture["attrs"].get("ERROR_CODE", {}).get("StringValue")
    assert zero_code == retry_code, (
        f"both twins failed the same way — an unreachable endpoint — so the DLQ ERROR_CODE must "
        f"match: zero-retry reported {zero_code!r}, {_RETRIES}-retry reported {retry_code!r} (H3)"
    )

    # --- second observable: neither DLQ has anything left in it. ---
    for label, queue in (("zero-retry", dlq_zero), (f"{_RETRIES}-retry", dlq_retry)):
        depth = _wait_counters_zero(
            ctx, sqs, queue["url"], ["ApproximateNumberOfMessages"]
        )["ApproximateNumberOfMessages"]
        assert depth == "0", (
            f"the {label} DLQ still reports ApproximateNumberOfMessages={depth!r} after both "
            f"arrivals were consumed, expected '0'"
        )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _best_effort(fn, what: str) -> None:
    """Run a teardown call; an error other than ResourceNotFoundException is reported as a leak."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise RuntimeError(f"could not {what}: {code}") from exc


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll until predicate holds; RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_counters_zero(ctx, sqs, queue_url, names, *, cap_s=90.0, interval_s=3.0):
    """Read the queue's *names* counters until each is "0" or cap_s ends; return the last read.

    SQS documents these counters as eventually consistent: they "may not achieve consistency until
    at least 1 minute after the producers stop sending messages" (GetQueueAttributes).
    """
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=list(names))["Attributes"]
        if all(attrs.get(n) == "0" for n in names):
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s counter wait ended (last={attrs!r}); not graded"
                )
            return attrs
        time.sleep(interval_s)


def _create_bus(ctx) -> tuple[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "bus")
    arn = events.create_event_bus(Name=name, Tags=_xsvc_tags_kv())["EventBusArn"]

    def _teardown(n=name):
        _best_effort(lambda: ctx.client("events").delete_event_bus(Name=n), f"delete event bus {n}")

    ctx.on_cleanup(_teardown)
    return name, arn


def _delete_connection(ctx, name: str) -> None:
    _best_effort(lambda: ctx.client("events").delete_connection(Name=name),
                 f"delete connection {name}")


def _delete_api_destination(ctx, name: str) -> None:
    _best_effort(lambda: ctx.client("events").delete_api_destination(Name=name),
                 f"delete api destination {name}")


def _create_events_role(ctx, *, invoke_api_destination: str) -> str:
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
        PolicyName="invoke-api-destination",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "events:InvokeApiDestination",
                        "Resource": invoke_api_destination,
                    }
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
    sqs = ctx.client("sqs")
    name = _xname(ctx, "dlq")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _put_rule_with_api_destination(
    ctx, bus: str, pattern: dict, dest_arn: str, role_arn: str, dlq: dict, *, retries: int
) -> dict[str, str]:
    """A rule whose only target is the API destination, with an explicit RetryPolicy and DLQ.
    MaximumEventAgeInSeconds is pinned to the maximum so event age never ends delivery.
    """
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    arn = events.put_rule(
        Name=name, EventBusName=bus, EventPattern=json.dumps(pattern), Tags=_xsvc_tags_kv()
    )["RuleArn"]

    def _teardown(n=name, b=bus):
        ev = ctx.client("events")
        _best_effort(lambda: ev.remove_targets(Rule=n, EventBusName=b, Ids=["t1"]),
                     f"remove target t1 from rule {n}")
        _best_effort(lambda: ev.delete_rule(Name=n, EventBusName=b, Force=True),
                     f"delete rule {n} on bus {b}")

    ctx.on_cleanup(_teardown)
    _allow_events_send(ctx, dlq, arn)
    events.put_targets(
        Rule=name,
        EventBusName=bus,
        Targets=[
            {
                "Id": "t1",
                "Arn": dest_arn,
                "RoleArn": role_arn,
                "RetryPolicy": {
                    "MaximumRetryAttempts": retries,
                    "MaximumEventAgeInSeconds": _MAX_EVENT_AGE_S,
                },
                "DeadLetterConfig": {"Arn": dlq["arn"]},
            }
        ],
    )
    return {"name": name, "arn": arn}


def _allow_events_send(ctx, queue: dict, rule_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventsSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )


def _body(msg: dict):
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _receive(ctx, queue_url: str, *, window_s: float) -> list[dict[str, Any]]:
    """Long-poll for up to window_s and return {body, attrs, at} for every message seen, deleting it."""
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            out.append(
                {
                    "body": _body(msg),
                    "attrs": msg.get("MessageAttributes") or {},
                    "at": time.monotonic(),
                }
            )
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if out:
            break
    return out


def _marker_of(captured: dict) -> str | None:
    body = captured.get("body")
    if not isinstance(body, dict):
        return None
    return (body.get("detail") or {}).get("marker")


def _await_marker(ctx, queue_url: str, marker: str, *, timeout_s: float):
    """Poll until the message carrying `marker` arrives; raises on timeout.
    Returns (captured, seconds waited, monotonic arrival time).
    """
    started = time.monotonic()
    strangers: list = []
    deadline = started + timeout_s
    while time.monotonic() < deadline:
        for captured in _receive(
            ctx, queue_url, window_s=min(8.0, max(1.0, deadline - time.monotonic()))
        ):
            if _marker_of(captured) == marker:
                return captured, time.monotonic() - started, captured["at"]
            strangers.append(_marker_of(captured))
    raise AssertionError(
        f"no dead-lettered message carrying detail.marker={marker!r} arrived on {queue_url} within "
        f"{timeout_s}s (markers seen meanwhile: {strangers})"
    )


def _collect_marker(ctx, queue_url: str, marker: str, *, timeout_s: float) -> list[dict[str, Any]]:
    """Every FURTHER copy of `marker` seen over a fixed window. Used as the exactly-once count."""
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for captured in _receive(
            ctx, queue_url, window_s=min(8.0, max(1.0, deadline - time.monotonic()))
        ):
            if _marker_of(captured) == marker:
                out.append(captured)
    return out


def _emit_until_dead_lettered(
    ctx, bus: str, source: str, dlq_url: str
) -> tuple[str, dict[str, Any], float]:
    """PutEvents with a fresh marker until one is dead-lettered on `dlq_url`; a new rule drops
    events until routing is live. Returns (marker, capture, monotonic send time of that attempt).
    """
    events = ctx.client("events")
    deadline = time.monotonic() + _LIVENESS_TIMEOUT_S
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        marker = uuid.uuid4().hex
        sent_at = time.monotonic()
        resp = events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": "Undeliverable",
                    "Detail": json.dumps({"marker": marker, "attempt": attempts}),
                    "EventBusName": bus,
                }
            ]
        )
        assert resp.get("FailedEntryCount") == 0, (
            f"PutEvents on bus {bus} must be accepted while establishing liveness, got {resp!r}"
        )
        for captured in _receive(ctx, dlq_url, window_s=25.0):
            if _marker_of(captured) == marker:
                return marker, captured, sent_at
    raise AssertionError(
        f"no event emitted on bus {bus} was dead-lettered on {dlq_url} after {attempts} PutEvents "
        f"attempts over {_LIVENESS_TIMEOUT_S}s — the zero-retry positive control could not be "
        f"established, so the retry-separation measurement is unprovable"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
