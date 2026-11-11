"""failed-invocations-records-the-bus-forwarding-the-destination-policy-denied."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failed-invocations-records-the-bus-forwarding-the-destination-policy-denied"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "events", "sqs"]

_SOURCE = "sim2real.nd.busdeny"
_DETAIL_TYPE = "BusForwardProbe"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition", ctx=None):
    """A bounded retry that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_queue(ctx, name, *, source_arn_like, check_tag):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventBridge",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {"ArnLike": {"aws:SourceArn": source_arn_like}},
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain(ctx, url, *, seconds, until=None):
    """Receive and delete for `seconds`, or until `until(received)` holds."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=max(1, min(5, int(left))),
            MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if until is not None and until(out):
            break
    return out


def _emit_until_delivered(ctx, events, bus, queue_url, *, timeout_s, poll_s=8.0, description="delivery"):
    """PutEvents with a fresh nonce until one reaches `queue_url`; returns (nonce, latency s).

    A new rule or target role silently drops events while it propagates, and a dropped event is
    never retried, so polling longer on a single attempt cannot recover it."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_nonce = None
    while time.monotonic() < deadline:
        nonce = uuid.uuid4().hex[:10]
        last_nonce = nonce
        sent_at = time.monotonic()
        resp = events.put_events(
            Entries=[
                {
                    "EventBusName": bus,
                    "Source": _SOURCE,
                    "DetailType": _DETAIL_TYPE,
                    "Detail": json.dumps({"nonce": nonce}),
                }
            ]
        )
        assert resp.get("FailedEntryCount") == 0, (
            f"PutEvents on {bus} was refused while establishing {description}: {resp!r}"
        )
        msgs = _drain(ctx, queue_url, seconds=poll_s,
                      until=lambda ms, n=nonce: any(n in m["Body"] for m in ms))
        if any(nonce in m["Body"] for m in msgs):
            return nonce, max(time.monotonic() - sent_at, 1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description} reaching {queue_url}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not established within {timeout_s}s: no emitted event reached "
        f"{queue_url} (last attempt carried nonce {last_nonce!r})"
    )


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _metric(ctx, metric, dims, *, since):
    """(Sum, datapoint_count). The pair matters: several AWS/Events metrics are only emitted when
    non-zero, so 'no datapoints' and 'a zero datapoint' are different observations."""
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/Events",
        MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in sorted(dims.items())],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    points = resp.get("Datapoints", [])
    return sum(p["Sum"] for p in points), len(points)


def _dlq_metric_sum(ctx, rule, *, since):
    """Sum across both spellings of the dead-letter metric: the docs table says
    `InvocationsSentToDlq`; some console surfaces show `InvocationsSentToDLQ`."""
    return sum(
        _metric(ctx, spelling, {"RuleName": rule}, since=since)[0]
        for spelling in ("InvocationsSentToDlq", "InvocationsSentToDLQ")
    )


def _ensure_forwarding_role(ctx, name, dst_bus_arn, check_tag):
    """A role EventBridge assumes to forward to the destination bus, created idempotently."""
    iam = ctx.client("iam")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=trust,
            Tags=[{"Key": "sim2real-check", "Value": check_tag}],
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda n=name: _delete_role(ctx, n))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityAlreadyExists":
            raise
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="sim2real-forward",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "events:PutEvents", "Resource": dst_bus_arn}
                ],
            }
        ),
    )
    return arn


def _delete_role(ctx, name):
    iam = ctx.client("iam")
    for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=name, PolicyName=pol)
    iam.delete_role(RoleName=name)


def _put_targets_ok(events, bus, rule, targets):
    resp = events.put_targets(Rule=rule, EventBusName=bus, Targets=targets)
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _teardown_rule(ctx, bus, rule, ids):
    events = ctx.client("events")
    events.remove_targets(Rule=rule, EventBusName=bus, Ids=ids, Force=True)
    events.delete_rule(Name=rule, EventBusName=bus, Force=True)


@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A destination bus policy Deny on the forwarding role blocks bus-to-bus delivery; the rule's
    TriggeredRules and a NO_PERMISSIONS dead letter record it, while FailedInvocations stays 0.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html
    """
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]
    pattern = json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]})
    src_bus = ctx.unique_name("sim2real-nd-fwd-src-")
    events.create_event_bus(Name=src_bus, Tags=[{"Key": "sim2real-check", "Value": check_tag}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=src_bus))
    dst_bus = ctx.unique_name("sim2real-nd-fwd-dst-")
    dst_bus_arn = events.create_event_bus(
        Name=dst_bus, Tags=[{"Key": "sim2real-check", "Value": check_tag}]
    )["EventBusArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=dst_bus))

    any_rule = f"arn:*:events:{ctx.region}:{account}:rule/*"
    ctl_url, ctl_arn = _make_queue(
        ctx, f"sim2real-nd-fwd-ctl-{suffix}", source_arn_like=any_rule, check_tag=check_tag
    )
    dst_url, dst_q_arn = _make_queue(
        ctx, f"sim2real-nd-fwd-dst-{suffix}", source_arn_like=any_rule, check_tag=check_tag
    )
    dlq_url, dlq_arn = _make_queue(
        ctx, f"sim2real-nd-fwd-dlq-{suffix}", source_arn_like=any_rule, check_tag=check_tag
    )

    # The consumer at the destination is the only place a delivery verdict is read.
    dst_rule = ctx.unique_name("sim2real-nd-fwd-dstrule-")
    events.put_rule(
        Name=dst_rule,
        EventBusName=dst_bus,
        EventPattern=pattern,
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )
    ctx.on_cleanup(lambda: _teardown_rule(ctx, dst_bus, dst_rule, ["q"]))
    _put_targets_ok(events, dst_bus, dst_rule, [{"Id": "q", "Arn": dst_q_arn}])

    # The twin control on the SOURCE bus: same pattern, same instant, a target nothing can deny.
    ctl_rule = ctx.unique_name("sim2real-nd-fwd-ctlrule-")
    events.put_rule(
        Name=ctl_rule,
        EventBusName=src_bus,
        EventPattern=pattern,
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )
    ctx.on_cleanup(lambda: _teardown_rule(ctx, src_bus, ctl_rule, ["q"]))
    _put_targets_ok(events, src_bus, ctl_rule, [{"Id": "q", "Arn": ctl_arn}])

    # The subject: forward source -> destination through a role that IS otherwise entitled.
    role_arn = _ensure_forwarding_role(
        ctx, f"sim2real-nd-fwd-role-{suffix}", dst_bus_arn, check_tag
    )
    fwd_rule = ctx.unique_name("sim2real-nd-fwd-rule-")
    events.put_rule(
        Name=fwd_rule,
        EventBusName=src_bus,
        EventPattern=pattern,
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )
    ctx.on_cleanup(lambda: _teardown_rule(ctx, src_bus, fwd_rule, ["bus"]))
    _put_targets_ok(
        events,
        src_bus,
        fwd_rule,
        [
            {
                "Id": "bus",
                "Arn": dst_bus_arn,
                "RoleArn": role_arn,
                "DeadLetterConfig": {"Arn": dlq_arn},
            }
        ],
    )

    # Prove both hops are live before anything is denied, absorbing rule/role propagation lag.
    _, ctl_latency = _emit_until_delivered(
        ctx,
        events,
        src_bus,
        ctl_url,
        timeout_s=200,
        description=f"the control rule {ctl_rule} on {src_bus} delivering to {ctl_url}",
    )
    _, fwd_latency = _emit_until_delivered(
        ctx,
        events,
        src_bus,
        dst_url,
        timeout_s=280,
        description=(
            f"the source rule {fwd_rule} forwarding {src_bus}->{dst_bus}, whose rule {dst_rule} "
            f"delivers to {dst_url} — the positive control for the whole two-hop path"
        ),
    )
    latency = max(ctl_latency, fwd_latency, 1.0)
    # Drain warm-up copies so the measured event is the only one in flight. The DLQ too: a warm-up
    # that raced the forwarding role's propagation can itself be dead-lettered with NO_PERMISSIONS.
    _drain(ctx, ctl_url, seconds=max(latency, 3.0))
    _drain(ctx, dst_url, seconds=max(latency, 3.0))
    _drain(ctx, dlq_url, seconds=max(latency, 3.0))

    # Break exactly one thing: an explicit Deny on the destination bus for the forwarding role.
    deny_sid = "Sim2realDenyForwarder"
    events.put_permission(
        EventBusName=dst_bus,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": deny_sid,
                        "Effect": "Deny",
                        "Principal": {"AWS": role_arn},
                        "Action": "events:PutEvents",
                        "Resource": dst_bus_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_permission(
            EventBusName=dst_bus, RemoveAllPermissions=True
        )
    )
    stored = events.describe_event_bus(Name=dst_bus).get("Policy", "")
    assert deny_sid in stored, (
        f"PutPermission did not attach the Deny to bus {dst_bus}: DescribeEventBus returns "
        f"Policy={stored!r} — nothing below would be attributable to a policy that is not there"
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    denied = f"denied-{uuid.uuid4().hex[:10]}"
    put = events.put_events(
        Entries=[
            {
                "EventBusName": src_bus,
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"nonce": denied}),
            }
        ]
    )
    assert put.get("FailedEntryCount") == 0, (
        f"PutEvents onto the SOURCE bus was refused: {put!r} — the Deny is on the destination bus "
        f"and must not turn the producer's own call into a rejection"
    )

    ctl = _poll_until(
        lambda: _drain(ctx, ctl_url, seconds=6,
                       until=lambda ms: any(denied in m["Body"] for m in ms)),
        lambda msgs: any(denied in m["Body"] for m in msgs),
        timeout_s=_budget_s(ctx, 180), ctx=ctx,
        interval_s=0,
        description=(
            f"the control rule {ctl_rule} on the source bus delivered {denied!r} while the "
            f"forwarding rule was denied — the in-file positive control B5 requires"
        ),
    )
    assert any(denied in m["Body"] for m in ctl), f"the control queue never carried {denied!r}"

    # The control has delivered; the absence is then held for a fixed window and confirmed by
    # queue depth.
    hold = 10.0
    leaked = _drain(ctx, dst_url, seconds=hold)
    assert leaked == [], (
        f"the destination bus's consumer received {len(leaked)} message(s) during a {hold:.0f}s hold "
        f"(after the control delivered) even though its bus policy denies "
        f"events:PutEvents for {role_arn}: {[m['Body'][:100] for m in leaked]!r}"
    )
    assert _queue_depth(ctx, dst_url) == 0, (
        f"the destination queue reports depth {_queue_depth(ctx, dst_url)} behind an empty receive — "
        f"the second independent observable disagrees with the first"
    )

    # TriggeredRules proves the rule matched, so the absence is a denial, not a missing send.
    triggered, _ = _poll_until(
        lambda: _metric(ctx, "TriggeredRules", {"EventBusName": src_bus, "RuleName": fwd_rule}, since=window_start),
        lambda pair: pair[0] >= 1,
        timeout_s=_budget_s(ctx, 300), ctx=ctx,
        interval_s=2,
        description=(
            f"AWS/Events TriggeredRules for {fwd_rule} shows the rule MATCHED the denied event — "
            f"without this, 'nothing arrived' is indistinguishable from 'nothing was ever sent'"
        ),
    )
    assert triggered >= 1, f"TriggeredRules Sum={triggered} for {fwd_rule}, expected >=1"

    # A bus target denied by the destination bus policy raises neither FailedInvocations nor
    # InvocationsSentToDlq; the dead letter with its ERROR_CODE is the producer-side record.
    # The denied rule's SuccessfulInvocationAttempts is too noisy to pin, so it is not asserted.
    dead = _poll_until(
        lambda: _drain(ctx, dlq_url, seconds=8, until=lambda ms: len(ms) >= 1),
        lambda msgs: len(msgs) >= 1,
        timeout_s=_budget_s(ctx, 240), ctx=ctx,
        interval_s=0,
        description=f"the denied forwarding was dead-lettered to {dlq_url}",
    )
    dead += _drain(ctx, dlq_url, seconds=2)
    assert len(dead) == 1, (
        f"the DLQ holds {len(dead)} message(s), expected exactly 1: "
        f"{[m['Body'][:100] for m in dead]!r}"
    )
    dead_body = json.loads(dead[0]["Body"])
    assert dead_body["detail"]["nonce"] == denied, (
        f"the dead-lettered payload carries nonce={dead_body['detail'].get('nonce')!r}, expected "
        f"{denied!r}: {dead_body!r}"
    )
    err = dead[0].get("MessageAttributes", {}).get("ERROR_CODE", {}).get("StringValue")
    assert err == "NO_PERMISSIONS", (
        f"the denied-forwarding DLQ copy carries ERROR_CODE={err!r}, expected exactly "
        f"'NO_PERMISSIONS' — measured on a real same-account destination-bus policy Deny "
        f"(attrs present: {sorted(dead[0].get('MessageAttributes', {}))!r})"
    )

    fwd_failed, fwd_failed_pts = _metric(ctx, "FailedInvocations", {"RuleName": fwd_rule}, since=window_start)
    assert (fwd_failed, fwd_failed_pts) == (0, 0), (
        f"FailedInvocations Sum={fwd_failed} over {fwd_failed_pts} datapoint(s) for {fwd_rule}, "
        f"expected 0/0 — measured twice on real AWS that this metric is NOT incremented for a "
        f"same-account bus-target permission denial (the DLQ above is the real producer-side signal)"
    )
    fwd_dlq_metric = _dlq_metric_sum(ctx, fwd_rule, since=window_start)
    assert fwd_dlq_metric == 0, (
        f"InvocationsSentToDlq(+DLQ) Sum={fwd_dlq_metric} for {fwd_rule}, expected 0 — measured "
        f"twice on real AWS that this metric is NOT incremented for an event-bus-type target even "
        f"though the event genuinely reaches the DLQ (asserted above)"
    )
    ctl_good, _ = _metric(
        ctx,
        "SuccessfulInvocationAttempts",
        {"EventBusName": src_bus, "RuleName": ctl_rule},
        since=window_start,
    )
    assert ctl_good >= 1, (
        f"SuccessfulInvocationAttempts Sum={ctl_good} for the CONTROL rule {ctl_rule}, expected >=1 "
        f"— the control's target was never denied and this metric IS emitted for that target type, "
        f"so its absence would mean the metric isn't observable at all in this account/window"
    )
    # Restore, and demand the next event (not the denied one) through the identical wiring.
    events.remove_permission(EventBusName=dst_bus, RemoveAllPermissions=True)
    after_policy = events.describe_event_bus(Name=dst_bus).get("Policy", "")
    assert deny_sid not in after_policy, (
        f"the Deny survived RemovePermission on {dst_bus}: Policy={after_policy!r}"
    )
    released = f"released-{uuid.uuid4().hex[:10]}"
    again = events.put_events(
        Entries=[
            {
                "EventBusName": src_bus,
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"nonce": released}),
            }
        ]
    )
    assert again.get("FailedEntryCount") == 0, f"the restore-leg PutEvents was refused: {again!r}"
    arrived = _poll_until(
        lambda: _drain(ctx, dst_url, seconds=8,
                       until=lambda ms: any(released in m["Body"] for m in ms)),
        lambda msgs: any(released in m["Body"] for m in msgs),
        timeout_s=_budget_s(ctx, 240), ctx=ctx,
        interval_s=0,
        description=(
            f"with the Deny removed, the identical rule/role/bus wiring forwarded {released!r} to "
            f"the destination consumer"
        ),
    )
    arrived += _drain(ctx, dst_url, seconds=2)
    nonces = sorted(json.loads(m["Body"])["detail"]["nonce"] for m in arrived)
    assert nonces == [released], (
        f"the destination consumer received {nonces!r} after the Deny was removed, expected exactly "
        f"[{released!r}] — the denied event was already dead-lettered and must not be replayed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
