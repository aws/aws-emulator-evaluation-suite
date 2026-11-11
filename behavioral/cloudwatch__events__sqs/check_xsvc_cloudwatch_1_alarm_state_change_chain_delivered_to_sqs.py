"""xsvc-cloudwatch-1-alarm-state-change-chain-delivered-to-sqs."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudwatch-1-alarm-state-change-chain-delivered-to-sqs"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "events", "sqs"]

_SOURCE = "aws.cloudwatch"
_DETAIL_TYPE = "CloudWatch Alarm State Change"
_PERIOD = 10  # high-resolution alarm: the evaluator runs per 10 s bucket
_THRESHOLD = 50.0
_HIGH = 90.0  # breaching for GreaterThanThreshold 50
_LOW = 10.0  # in range
_METRIC = "Load"


# ===== helpers =====
_POLL_BUDGET_S = 240.0  # a ceiling for a poll to FAIL at; never asserted as a latency


def _now_bucket():
    epoch = int(time.time())
    return datetime.fromtimestamp(epoch - epoch % _PERIOD, tz=timezone.utc)


def _wait_for_bucket(bucket):
    """Block until the wall clock is inside `bucket`, so a value lands in a fresh period."""
    while datetime.now(timezone.utc) < bucket:
        time.sleep(0.5)


def _put(cw, namespace, bucket, value):
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": _METRIC, "Timestamp": bucket, "Value": value, "StorageResolution": 1}
        ],
    )


def _describe(cw, name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[name], AlarmTypes=["MetricAlarm"]
    ):
        for a in page.get("MetricAlarms", []):
            if a["AlarmName"] == name:
                return a
    raise AssertionError(f"alarm {name!r} is not present in DescribeAlarms")


def _create_alarm(ctx, cw, name, namespace):
    cw.put_metric_alarm(
        AlarmName=name,
        AlarmDescription=f"sim2real {CHECK}",
        Namespace=namespace,
        MetricName=_METRIC,
        Statistic="Maximum",
        Period=_PERIOD,
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        _tolerant(lambda n=name: ctx.client("cloudwatch").delete_alarms(AlarmNames=[n]), "ResourceNotFound")
    )
    return _describe(cw, name)["AlarmArn"]


def _make_queue(ctx, name):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(_tolerant(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u), *_SQS_NF))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _allow_rule_to_send(ctx, url, queue_arn, rule_arn):
    """Least privilege: events.amazonaws.com may SendMessage ONLY on behalf of this one rule."""
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowOneRule",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )


def _make_rule(ctx, name, pattern, target_ids):
    events = ctx.client("events")
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(_tolerant(lambda: _teardown_rule(ctx, name, target_ids), "ResourceNotFoundException"))
    return arn


def _teardown_rule(ctx, name, target_ids):
    events = ctx.client("events")
    events.remove_targets(Rule=name, Ids=target_ids, Force=True)
    events.delete_rule(Name=name, Force=True)


def _put_targets_ok(events, rule, targets):
    resp = events.put_targets(Rule=rule, Targets=targets)
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _drain_into(ctx, url, inbox, *, seconds):
    """Receive-and-delete for `seconds`, appending parsed bodies to `inbox`. `.get("Messages", [])`
    feeds a list whose content is asserted exactly below — the sanctioned polarity."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            inbox.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return inbox


def _events_for(inbox, alarm_arn):
    """Events naming this alarm, de-duplicated by EventBridge event id (delivery is at-least-once),
    in transition order (a standard queue does not preserve it)."""
    by_id = {}
    for e in inbox:
        if alarm_arn in (e.get("resources") or []):
            by_id.setdefault(e["id"], e)
    return sorted(by_id.values(), key=lambda e: e["detail"]["state"]["timestamp"])


def _await_events(ctx, url, inbox, alarm_arn, count, what):
    deadline = time.monotonic() + _POLL_BUDGET_S
    while True:
        _drain_into(ctx, url, inbox, seconds=4)
        got = _events_for(inbox, alarm_arn)
        if len(got) >= count:
            return got
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what}: the queue delivered {len(got)} event(s) for {alarm_arn}, expected "
                f"{count}; states seen {[e['detail']['state']['value'] for e in got]!r}"
            )


def _drive_until(cw, alarm, publish, want, what):
    """Keep publishing and polling until the alarm reaches `want`; FAIL (never skip) on exhaustion."""
    deadline = time.monotonic() + _POLL_BUDGET_S
    while True:
        if publish is not None:
            publish()
        state = _describe(cw, alarm)
        if state["StateValue"] == want:
            return state
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what} never happened; last state {state['StateValue']!r} "
                f"reason {state['StateReason']!r}"
            )
        time.sleep(2.0)


def _ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(timezone.utc)


def _nonempty(v) -> bool:
    return isinstance(v, str) and bool(v.strip())


def _rule_live_barrier(cw, canary, delivered, what):
    """EventBridge rule creation is eventually consistent and exposes no 'live' flag, so liveness is
    observed: toggle a canary alarm ALARM <-> OK via SetAlarmState until ANY canary event is
    delivered. Measured: a single SetAlarmState issued right after PutTargets was lost (the rule
    was not live yet) while the canary's later evaluator-driven transition arrived."""
    deadline = time.monotonic() + _POLL_BUDGET_S
    flips = 0
    while True:
        cw.set_alarm_state(
            AlarmName=canary,
            StateValue=("ALARM", "OK")[flips % 2],
            StateReason="sim2real rule-liveness barrier",
        )
        flips += 1
        if delivered():
            return flips
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: no canary event delivered after {flips} transitions")


# ===== the check =====
# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Real metric data drives an alarm INSUFFICIENT_DATA -> ALARM -> OK -> INSUFFICIENT_DATA, and
    each transition reaches SQS through a default-bus EventBridge rule as a linked chain: every
    event's previousState is exactly the prior event's state, and reasonData names the published data."""
    cw = ctx.client("cloudwatch")
    events = ctx.client("events")
    account = ctx.account
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    namespace = ctx.unique_name("Sim2RealXsvcCw1Chain")
    alarm = ctx.unique_name("sim2real-xsvc-cw1-chain-")
    canary = ctx.unique_name("sim2real-xsvc-cw1-canary-")
    started = datetime.now(timezone.utc) - timedelta(seconds=5)

    # --- wiring: queue <- rule (default bus) with a policy scoped to that rule's ARN ------------
    queue_name = ctx.unique_name("sim2real-xsvc-cw1-chain-q-")
    url, queue_arn = _make_queue(ctx, queue_name)
    rule = ctx.unique_name("sim2real-xsvc-cw1-chain-r-")
    rule_arn = _make_rule(
        ctx, rule, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}, ["q"]
    )
    _allow_rule_to_send(ctx, url, queue_arn, rule_arn)
    _put_targets_ok(events, rule, [{"Id": "q", "Arn": queue_arn}])
    inbox: list = []

    # --- barrier: the rule is live before the first REAL transition can happen -----------------
    canary_arn = _create_alarm(ctx, cw, canary, namespace + "Canary")
    _rule_live_barrier(
        cw,
        canary,
        lambda: bool(_events_for(_drain_into(ctx, url, inbox, seconds=4), canary_arn)),
        "the default-bus rule becoming live",
    )
    _gone_alarm(ctx, canary)

    # --- the alarm under test, created only now --------------------------------------------------
    alarm_arn = _create_alarm(ctx, cw, alarm, namespace)
    assert alarm_arn == f"arn:{partition}:cloudwatch:{ctx.region}:{account}:alarm:{alarm}", (
        f"DescribeAlarms AlarmArn {alarm_arn!r} is not the documented alarm ARN form"
    )
    initial = _describe(cw, alarm)
    assert initial["StateValue"] == "INSUFFICIENT_DATA" and _nonempty(initial["StateReason"]), (
        f"new alarm reported {initial['StateValue']!r}/{initial['StateReason']!r}"
    )

    high_buckets: set = set()
    low_buckets: set = set()

    def publish_high():
        b = _now_bucket()
        _put(cw, namespace, b, _HIGH)
        high_buckets.add(b)

    _drive_until(cw, alarm, publish_high, "ALARM", f"breaching data ({_HIGH}) driving ALARM")

    _wait_for_bucket(max(high_buckets) + timedelta(seconds=_PERIOD))

    def publish_low():
        b = _now_bucket()
        if b in high_buckets:
            return
        _put(cw, namespace, b, _LOW)
        low_buckets.add(b)

    _drive_until(cw, alarm, publish_low, "OK", f"recovering data ({_LOW}) driving OK")
    last_published = max(low_buckets)

    # Publishing STOPS here. TreatMissingData=missing must take the alarm to INSUFFICIENT_DATA.
    _drive_until(
        cw, alarm, None, "INSUFFICIENT_DATA", "missing data (no further publishes) driving "
        "INSUFFICIENT_DATA"
    )

    chain = _await_events(ctx, url, inbox, alarm_arn, 3, "the three real transitions")
    _drain_into(ctx, url, inbox, seconds=6)  # absorb any at-least-once duplicate before counting
    chain = _events_for(inbox, alarm_arn)
    states = [e["detail"]["state"]["value"] for e in chain]
    assert states == ["ALARM", "OK", "INSUFFICIENT_DATA"], (
        f"the queue holds transitions {states!r} for {alarm}, expected exactly "
        f"['ALARM', 'OK', 'INSUFFICIENT_DATA'] (de-duplicated by event id, ordered by state time)"
    )

    # --- envelope, per event ----------------------------------------------------------------------
    for e in chain:
        st = e["detail"]["state"]
        assert e["source"] == _SOURCE, f"source {e['source']!r} != {_SOURCE!r}"
        assert e["detail-type"] == _DETAIL_TYPE, f"detail-type {e['detail-type']!r}"
        assert e["resources"] == [alarm_arn], (
            f"resources {e['resources']!r}, expected exactly [{alarm_arn!r}]"
        )
        assert e["account"] == account, f"account {e['account']!r}, caller is {account!r}"
        assert e["region"] == ctx.region, f"region {e['region']!r}, expected {ctx.region!r}"
        assert e["version"] == "0", f"envelope version {e.get('version')!r}"
        assert e["detail"]["alarmName"] == alarm, f"alarmName {e['detail']['alarmName']!r}"
        assert _ts(st["timestamp"]) >= started, (
            f"{st['value']} state timestamp {st['timestamp']!r} predates this run"
        )
        assert e["time"] == _ts(st["timestamp"]).strftime("%Y-%m-%dT%H:%M:%SZ"), (
            f"envelope time {e['time']!r} is not the {st['value']} state timestamp "
            f"{st['timestamp']!r} at second precision"
        )
        stat = e["detail"]["configuration"]["metrics"][0]["metricStat"]
        assert (stat["metric"]["namespace"], stat["metric"]["name"], stat["period"],
                stat["stat"]) == (namespace, _METRIC, _PERIOD, "Maximum"), (
            f"configuration.metricStat {stat!r} does not describe the alarm's metric"
        )

    alarm_e, ok_e, insuff_e = chain

    # --- the chain: each previousState IS the prior state, byte for byte ------------------------
    first_prev = alarm_e["detail"]["previousState"]
    assert first_prev["value"] == "INSUFFICIENT_DATA" and _nonempty(first_prev.get("reason")), (
        f"the ALARM event's previousState is {first_prev!r}, expected the creation state "
        f"INSUFFICIENT_DATA with a non-empty reason"
    )
    assert first_prev.get("reason") == initial["StateReason"], (
        f"the ALARM event's previousState reason {first_prev.get('reason')!r} is not the creation "
        f"state's DescribeAlarms reason {initial['StateReason']!r}"
    )
    assert "reasonData" not in first_prev, (
        f"the creation state carries reasonData {first_prev.get('reasonData')!r}; real AWS "
        f"evaluated nothing at creation and sends none"
    )
    assert ok_e["detail"]["previousState"] == alarm_e["detail"]["state"], (
        f"the OK event's previousState {ok_e['detail']['previousState']!r} is not the ALARM "
        f"event's state {alarm_e['detail']['state']!r}"
    )
    assert insuff_e["detail"]["previousState"] == ok_e["detail"]["state"], (
        f"the INSUFFICIENT_DATA event's previousState {insuff_e['detail']['previousState']!r} is "
        f"not the OK event's state {ok_e['detail']['state']!r}"
    )

    # --- reason + reasonData, per state -----------------------------------------------------------
    def _rd(e):
        rd = json.loads(e["detail"]["state"]["reasonData"])
        assert (rd["version"], rd["statistic"], rd["period"]) == ("1.0", "Maximum", _PERIOD), (
            f"{e['detail']['state']['value']} reasonData header {rd!r}"
        )
        assert rd["threshold"] == _THRESHOLD, (
            f"{e['detail']['state']['value']} reasonData.threshold {rd['threshold']!r}, the alarm's "
            f"threshold is {_THRESHOLD!r}"
        )
        return rd

    for e, value, buckets in (
        (alarm_e, _HIGH, high_buckets),
        (ok_e, _LOW, low_buckets),
    ):
        st = e["detail"]["state"]
        rd = _rd(e)
        assert rd["recentDatapoints"] == [value], (
            f"{st['value']} recentDatapoints {rd['recentDatapoints']!r}, expected [{value!r}]"
        )
        ev = rd["evaluatedDatapoints"]
        assert len(ev) == 1 and set(ev[0]) == {"timestamp", "sampleCount", "value"}, (
            f"{st['value']} evaluatedDatapoints {ev!r}, expected one full datapoint"
        )
        bucket = _ts(ev[0]["timestamp"])
        assert ev[0]["value"] == value and bucket in buckets, (
            f"{st['value']} evaluated {ev[0]!r}; this check published {value!r} into "
            f"{sorted(b.isoformat() for b in buckets)!r}"
        )
        assert ev[0]["sampleCount"] >= 1.0, f"sampleCount {ev[0]['sampleCount']!r}"
        assert _ts(rd["startDate"]) == bucket, (
            f"{st['value']} startDate {rd['startDate']!r} is not the evaluated bucket"
        )
        assert _nonempty(st.get("reason")), f"{st['value']} reason {st.get('reason')!r} is empty"

    ist = insuff_e["detail"]["state"]
    assert _nonempty(ist.get("reason")), f"INSUFFICIENT_DATA reason {ist.get('reason')!r} is empty"
    rd = _rd(insuff_e)
    assert rd["recentDatapoints"] == [], (
        f"INSUFFICIENT_DATA recentDatapoints {rd['recentDatapoints']!r}, expected [] (no data)"
    )
    ev = rd["evaluatedDatapoints"]
    assert len(ev) == 1 and set(ev[0]) == {"timestamp"}, (
        f"INSUFFICIENT_DATA evaluatedDatapoints {ev!r}, expected one value-less (unknown) bucket"
    )
    assert _ts(ev[0]["timestamp"]) > last_published, (
        f"the unknown bucket {ev[0]['timestamp']!r} is not after the last published bucket "
        f"{last_published.isoformat()} — the evaluator called a bucket with data 'unknown'"
    )

    final = _describe(cw, alarm)
    assert (final["StateValue"], final["StateReason"]) == ("INSUFFICIENT_DATA", ist["reason"]), (
        f"DescribeAlarms {final['StateValue']!r}/{final['StateReason']!r} disagrees with the last "
        f"delivered event {ist['value']!r}/{ist['reason']!r}"
    )
    assert json.loads(final["StateReasonData"]) == rd, (
        f"DescribeAlarms StateReasonData {final['StateReasonData']!r} != delivered {rd!r}"
    )

    # Tear down in reverse dependency order and prove each resource gone.
    _gone_alarm(ctx, alarm)
    _gone_rule(ctx, rule, ["q"])
    _gone_queue(ctx, queue_name, url)


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``.

    AWS sends some errors with an empty message (CloudWatch ResourceNotFound): ``message`` is "".
    """
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message is {msg!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
_SQS_NF_MSG = "The specified queue does not exist."


def _gone_alarm(ctx, name: str) -> None:
    cw = ctx.client("cloudwatch")
    cw.delete_alarms(AlarmNames=[name])
    # AWS has no not-found code for DescribeAlarms: the in-band miss is beat 1.
    by_name = cw.describe_alarms(AlarmNames=[name])
    assert not by_name.get("MetricAlarms") and not by_name.get("CompositeAlarms"), f"DescribeAlarms still returns deleted alarm {name}"
    listed = {a["AlarmName"] for a in cw.describe_alarms(AlarmNamePrefix=name).get("MetricAlarms", [])}
    assert name not in listed, f"DescribeAlarms(prefix) still lists deleted alarm {name}"
    _refused(lambda: cw.set_alarm_state(AlarmName=name, StateValue="OK", StateReason="gone"),
             ("ResourceNotFound",), 404, f"SetAlarmState {name}", "")


def _gone_rule(ctx, name: str, target_ids: list[str], bus: str = "default") -> None:
    ev = ctx.client("events")
    if target_ids:
        ev.remove_targets(Rule=name, EventBusName=bus, Ids=target_ids)
    ev.delete_rule(Name=name, EventBusName=bus)
    nf = ("ResourceNotFoundException",)
    missing = f"Rule {name} does not exist on EventBus {bus}."
    _poll_refused(lambda: ev.describe_rule(Name=name, EventBusName=bus), nf, 400, f"DescribeRule {name}", missing)
    listed = {r["Name"] for r in ev.list_rules(NamePrefix=name, EventBusName=bus).get("Rules", [])}
    assert name not in listed, f"ListRules still lists deleted rule {name}"
    _refused(
        lambda: ev.put_targets(Rule=name, EventBusName=bus, Targets=[{"Id": "gone", "Arn": f"arn:aws:sqs:{ctx.region}:{ctx.account}:gone"}]),
        nf, 400, f"PutTargets {name}", missing,
    )


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_NF_MSG)
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}",
             _SQS_NF_MSG)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
