"""alarm-log-metric-chain-lambda-error-lines-breach-alarm-and-reach-sqs."""

from __future__ import annotations

import io
import json
import re
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-log-metric-chain-lambda-error-lines-breach-alarm-and-reach-sqs"

GROUP = "alerting"

SERVICES = ["cloudwatch", "lambda", "logs", "sns", "sqs"]

_BURST = 5
_THRESHOLD = 3.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Lambda ERROR lines reach the log group, the metric filter counts exactly those lines on the
    extracted dimension, the evaluator moves the alarm to ALARM citing that datapoint, and the SNS
    notification in the queue names the filter metric and dimension."""
    window_start = datetime.now(timezone.utc) - timedelta(minutes=10)
    account = ctx.client("sts").get_caller_identity()["Account"]
    cw = ctx.client("cloudwatch")

    topic, queue = _topic_to_queue(ctx)
    src = _lambda_source(ctx)
    namespace = ctx.unique_name("Sim2Real/AlarmChain/")
    metric = "ChainErrorLines"
    _put_filter(ctx, src["group"], _xname(ctx, "mf"), _pattern("ERROR", src["marker"]),
                namespace, metric)
    _warm(ctx, src, namespace, metric, "ERROR", window_start)

    alarm = _create_alarm(ctx, namespace, metric, "burst", _THRESHOLD, [topic["arn"]])

    # ---- the single cause: _BURST ERROR lines, one per invocation ----
    printed = [_invoke(ctx, src, "ERROR", "burst", seq) for seq in range(_BURST)]

    # ---- hop 1: every line landed in the function's log group, field by field ----
    events = _await_lines(ctx, src, "burst", _BURST)
    seqs = sorted(e["parsed"]["seq"] for e in events)
    assert seqs == list(range(_BURST)), f"log events carry seqs {seqs!r}, expected 0..{_BURST - 1}"
    for e in events:
        assert e["message"].strip() in printed, (
            f"log event message {e['message']!r} is not a line the function printed ({printed!r})"
        )
        assert e["parsed"]["level"] == "ERROR" and e["parsed"]["marker"] == src["marker"], e
        assert _STREAM_RE.match(e["logStreamName"]), (
            f"Lambda log stream name {e['logStreamName']!r} does not have the documented "
            f"YYYY/MM/DD/[$LATEST]<32 hex> layout"
        )

    # ---- hop 2: the filter produced exactly one unit per matched line on Batch=burst ----
    dps = _await_metric_sum(ctx, namespace, metric, "burst", window_start, _BURST)
    total = sum(dp["Sum"] for dp in dps)
    samples = sum(dp["SampleCount"] for dp in dps)
    assert total == float(_BURST), f"filter metric Sum over the burst is {total!r}, expected {_BURST}"
    assert samples == float(_BURST), (
        f"filter metric SampleCount over the burst is {samples!r}, expected {_BURST} (one per line)"
    )
    per_minute = {dp["Timestamp"].replace(second=0, microsecond=0): dp["Sum"] for dp in dps}

    # ---- hop 3: the alarm evaluator read those datapoints and breached ----
    desc = _await_state(ctx, alarm, "ALARM", timeout_s=600)
    reason = json.loads(desc["StateReasonData"])
    assert reason.get("statistic") == "Sum", f"StateReasonData.statistic {reason!r}"
    assert reason.get("period") == 60, f"StateReasonData.period {reason!r}"
    assert float(reason.get("threshold")) == _THRESHOLD, f"StateReasonData.threshold {reason!r}"
    evaluated = reason.get("evaluatedDatapoints") or []
    assert len(evaluated) == 1, f"one evaluation period must cite one datapoint, got {evaluated!r}"
    cited = evaluated[0]
    value = float(cited["value"])
    assert _THRESHOLD <= value <= _BURST, (
        f"the breaching datapoint {value!r} must be >= threshold {_THRESHOLD} and cannot exceed the "
        f"{_BURST} ERROR lines caused; reason data {reason!r}"
    )
    assert float(cited["sampleCount"]) == value, (
        f"each matched line contributes metricValue 1, so sampleCount must equal value: {cited!r}"
    )
    cited_ts = datetime.fromisoformat(cited["timestamp"].replace("Z", "+00:00")).replace(
        second=0, microsecond=0)
    assert cited_ts in per_minute, (
        f"the alarm cited minute {cited_ts.isoformat()} but the filter metric has datapoints only "
        f"at {sorted(t.isoformat() for t in per_minute)!r}"
    )
    assert value <= per_minute[cited_ts], (
        f"the alarm cited {value!r} for {cited_ts.isoformat()}, more than the filter metric's "
        f"final Sum {per_minute[cited_ts]!r} for that minute"
    )
    history = _history(ctx, alarm, "StateUpdate")
    to_alarm = [h for h in history if json.loads(h["HistoryData"])["newState"]["stateValue"] == "ALARM"]
    assert to_alarm, f"alarm history records no transition to ALARM: {[h['HistorySummary'] for h in history]!r}"
    actions = _history(ctx, alarm, "Action")
    assert any(topic["arn"] in h["HistorySummary"] for h in actions), (
        f"alarm history records no action against {topic['arn']}: "
        f"{[h['HistorySummary'] for h in actions]!r}"
    )

    # ---- hops 4+5: SNS delivered the notification to SQS, attributing the custom metric ----
    envelope, payload = _await_payload(
        ctx, queue["url"], lambda p: p.get("AlarmName") == alarm and p.get("NewStateValue") == "ALARM",
        timeout_s=300, description=f"ALARM notification for {alarm}",
    )
    assert envelope["Type"] == "Notification", envelope
    assert envelope["TopicArn"] == topic["arn"], f"envelope TopicArn {envelope['TopicArn']!r}"
    assert envelope.get("Subject", "").startswith(f'ALARM: "{alarm}"'), (
        f"envelope Subject {envelope.get('Subject')!r}"
    )
    assert payload["AWSAccountId"] == account, f"AWSAccountId {payload['AWSAccountId']!r} != {account!r}"
    assert payload["AlarmArn"] == desc["AlarmArn"], f"AlarmArn {payload['AlarmArn']!r} != {desc['AlarmArn']!r}"
    trigger = payload.get("Trigger") or {}
    assert trigger.get("MetricName") == metric, f"Trigger must name the filter metric: {trigger!r}"
    assert trigger.get("Namespace") == namespace, f"Trigger must name the filter namespace: {trigger!r}"
    assert str(trigger.get("Statistic", "")).upper() == "SUM", f"Trigger.Statistic {trigger!r}"
    assert trigger.get("Period") == 60 and trigger.get("EvaluationPeriods") == 1, trigger
    assert float(trigger.get("Threshold")) == _THRESHOLD, f"Trigger.Threshold {trigger!r}"
    dims = {d.get("name"): d.get("value") for d in trigger.get("Dimensions", [])}
    assert dims == {"Batch": "burst"}, f"Trigger.Dimensions must be the extracted Batch=burst: {trigger!r}"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}

_STREAM_RE = re.compile(r"^\d{4}/\d{2}/\d{2}/\[\$LATEST\][0-9a-f]{32}$")

_HANDLER_SRC = '''
import json


def handler(event, context):
    line = json.dumps(
        {"level": event["level"], "marker": event["marker"], "batch": event["batch"],
         "seq": event["seq"]},
        separators=(",", ":"),
    )
    print(line)
    return {"printed": line}
'''

_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<hex>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within the {timeout_s}s poll budget. Last: {last!r}")


def _error_code(fn) -> str:
    """The AWS error code fn raises. An unexpected SUCCESS raises, never returns a falsy code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"call was expected to fail but succeeded: {result!r}")


def _pattern(level: str, marker: str) -> str:
    return f'{{ ($.level = "{level}") && ($.marker = "{marker}") }}'


def _zip_bytes(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    for pol in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
    for pol_name in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=pol_name)
    iam.delete_role(RoleName=name)


def _reap_log_group(ctx, name: str) -> None:
    """delete_function does not remove /aws/lambda/<fn>, and a late flush can RECREATE it, so
    delete, then watch for reappearance over a bounded window; raise if it never settles."""
    logs = ctx.client("logs")
    absent_rounds = 0
    for _ in range(12):
        present = any(
            g["logGroupName"] == name
            for g in logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
        )
        if present:
            absent_rounds = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError:
                pass
        else:
            absent_rounds += 1
            if absent_rounds >= 3:
                return
        time.sleep(5)
    raise RuntimeError(f"log group {name} still reappearing after bounded reap")


def _lambda_source(ctx) -> dict[str, str]:
    """A Lambda that prints one JSON line per invoke into a log group this check pre-created.

    The log-group reap is registered BEFORE the function exists, so LIFO runs it after the
    function is deleted. Log delivery is proven (a `prime` line is read back) before returning,
    so IAM propagation of the execution role cannot silently drop a counted line later.
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    fn_name = _xname(ctx, "fn")
    group = f"/aws/lambda/{fn_name}"
    logs.create_log_group(logGroupName=group, tags=_MANAGED_TAGS)
    ctx.on_cleanup(lambda: _reap_log_group(ctx, group))
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)

    role_name = _xname(ctx, "role")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )

    kwargs = dict(
        FunctionName=fn_name, Runtime="python3.12", Role=role_arn,
        Handler="lambda_function.handler", Code={"ZipFile": _zip_bytes(_HANDLER_SRC)},
        Timeout=15, MemorySize=128, Tags=dict(_MANAGED_TAGS),
    )
    last_err = None
    for _ in range(12):  # IAM propagation: the new role is not yet assumable by Lambda
        try:
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(5)
    else:
        raise AssertionError(f"create_function never accepted the new role: {last_err!r}")
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
        lambda s: s in ("Active", "Failed"), timeout_s=180, interval_s=3,
        description=f"function {fn_name} leaving Pending",
    )
    state = lam.get_function_configuration(FunctionName=fn_name)["State"]
    assert state == "Active", f"function {fn_name} is {state!r}, expected Active"

    src = {"fn": fn_name, "group": group, "marker": ctx.unique_name("mk")}
    counter = {"n": 0}

    def _prime_and_read():
        _invoke(ctx, src, "INFO", "prime", counter["n"])
        counter["n"] += 1
        return _read_lines(ctx, src, "prime")

    _poll_until(_prime_and_read, lambda ev: len(ev) >= 1, timeout_s=300, interval_s=10,
                description=f"a printed line reaching log group {group}")
    return src


def _invoke(ctx, src: dict, level: str, batch: str, seq: int) -> str:
    payload = {"level": level, "marker": src["marker"], "batch": batch, "seq": seq}
    resp = ctx.client("lambda").invoke(
        FunctionName=src["fn"], InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = json.loads(resp["Payload"].read())
    assert resp.get("FunctionError") is None, f"invoke {payload!r} failed: {body!r}"
    return body["printed"]


def _read_lines(ctx, src: dict, batch: str) -> list[dict]:
    """Every log event in src's group carrying this marker and batch, with its message parsed."""
    logs = ctx.client("logs")
    pattern = f'{{ ($.marker = "{src["marker"]}") && ($.batch = "{batch}") }}'
    out = []
    for page in logs.get_paginator("filter_log_events").paginate(
        logGroupName=src["group"], filterPattern=pattern
    ):
        for ev in page.get("events", []):
            ev = dict(ev)
            ev["parsed"] = json.loads(ev["message"])
            out.append(ev)
    return out


def _await_lines(ctx, src: dict, batch: str, n: int) -> list[dict]:
    events = _poll_until(
        lambda: _read_lines(ctx, src, batch), lambda ev: len(ev) >= n, timeout_s=300,
        interval_s=5, description=f"{n} '{batch}' lines in {src['group']}",
    )
    assert len(events) == n, (
        f"{len(events)} '{batch}' log events in {src['group']}, but {n} lines were printed: "
        f"{[e['message'] for e in events]!r}"
    )
    return events


def _put_filter(ctx, group: str, name: str, pattern: str, namespace: str, metric: str) -> None:
    """A metric filter emitting 1 per matched line, dimensioned by the line's own batch field.
    No defaultValue: a non-matching line must publish nothing."""
    ctx.client("logs").put_metric_filter(
        logGroupName=group, filterName=name, filterPattern=pattern,
        metricTransformations=[{
            "metricName": metric, "metricNamespace": namespace, "metricValue": "1",
            "dimensions": {"Batch": "$.batch"},
        }],
    )
    ctx.on_cleanup(lambda: _delete_filter_quiet(ctx, group, name))


def _delete_filter_quiet(ctx, group: str, name: str) -> None:
    try:
        ctx.client("logs").delete_metric_filter(logGroupName=group, filterName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _metric_datapoints(ctx, namespace: str, metric: str, batch: str, start: datetime) -> list[dict]:
    return ctx.client("cloudwatch").get_metric_statistics(
        Namespace=namespace, MetricName=metric,
        Dimensions=[{"Name": "Batch", "Value": batch}],
        StartTime=start, EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60, Statistics=["Sum", "SampleCount"],
    ).get("Datapoints", [])


def _await_metric_sum(ctx, namespace, metric, batch, start, n) -> list[dict]:
    return _poll_until(
        lambda: _metric_datapoints(ctx, namespace, metric, batch, start),
        lambda dps: sum(dp["Sum"] for dp in dps) >= n, timeout_s=420, interval_s=10,
        description=f"{namespace}/{metric} Batch={batch} reaching Sum {n}",
    )


def _warm(ctx, src: dict, namespace: str, metric: str, level: str, start: datetime) -> None:
    """Prove the filter is live: invoke `warm` lines until one is counted on Batch=warm."""
    _warm_batch(ctx, src, namespace, metric, level, "warm", start)


def _warm_batch(ctx, src, namespace, metric, level, batch, start) -> None:
    """Invoke `level` lines on `batch` until the filter has counted at least one of them."""
    counter = {"n": 0}

    def _emit_and_read():
        _invoke(ctx, src, level, batch, counter["n"])
        counter["n"] += 1
        return _metric_datapoints(ctx, namespace, metric, batch, start)

    _poll_until(_emit_and_read, lambda dps: sum(dp["Sum"] for dp in dps) >= 1, timeout_s=420,
                interval_s=15, description=f"filter {namespace}/{metric} counting a {level} {batch} line")


def _create_alarm(ctx, namespace, metric, batch, threshold, actions) -> str:
    cw = ctx.client("cloudwatch")
    name = _xname(ctx, "alarm")
    cw.put_metric_alarm(
        AlarmName=name, Namespace=namespace, MetricName=metric,
        Dimensions=[{"Name": "Batch", "Value": batch}],
        Statistic="Sum", Period=60, EvaluationPeriods=1, DatapointsToAlarm=1,
        Threshold=threshold, ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching", ActionsEnabled=True, AlarmActions=list(actions),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    ctx.on_cleanup(lambda: ctx.client("cloudwatch").delete_alarms(AlarmNames=[name]))
    return name


def _describe_alarm(ctx, name: str) -> dict:
    alarms = ctx.client("cloudwatch").describe_alarms(AlarmNames=[name])["MetricAlarms"]
    assert len(alarms) == 1, f"describe_alarms({name!r}) returned {len(alarms)} alarms"
    return alarms[0]


def _await_state(ctx, name: str, state: str, timeout_s: float = 600) -> dict:
    return _poll_until(
        lambda: _describe_alarm(ctx, name), lambda a: a["StateValue"] == state,
        timeout_s=timeout_s, interval_s=10, description=f"alarm {name} evaluating to {state}",
    )


def _history(ctx, name: str, item_type: str) -> list[dict]:
    cw = ctx.client("cloudwatch")
    out = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name, HistoryItemType=item_type
    ):
        out.extend(page.get("AlarmHistoryItems", []))
    return out


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), tags=dict(_MANAGED_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _subscribe_queue(ctx, topic_arn: str, queue: dict) -> str:
    """Grant the topic SendMessage on the queue and subscribe it. Returns the subscription ARN."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue["arn"],
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    ctx.client("sqs").set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})
    sub = ctx.client("sns").subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue["arn"], ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: _unsubscribe_quiet(ctx, sub))
    return sub


def _unsubscribe_quiet(ctx, sub_arn: str) -> None:
    try:
        ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


def _topic_to_queue(ctx) -> tuple[dict, dict]:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=_xname(ctx, "topic"), Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]
    )["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=arn))
    queue = _create_queue(ctx)
    queue["sub"] = _subscribe_queue(ctx, arn, queue)
    return {"arn": arn}, queue


def _alarm_payload(raw: str) -> tuple[dict, dict] | None:
    """(SNS envelope, alarm payload) for one SQS body, or None if it is not an alarm notification."""
    try:
        envelope = json.loads(raw)
        payload = json.loads(envelope["Message"])
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or "AlarmName" not in payload:
        return None
    return envelope, payload


def _receive_round(ctx, queue_url: str) -> list[tuple[dict, dict]]:
    sqs = ctx.client("sqs")
    got = []
    for msg in sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=10).get("Messages", []):
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        parsed = _alarm_payload(msg.get("Body", ""))
        if parsed is not None:
            got.append(parsed)
    return got


def _await_payload(ctx, queue_url, predicate, *, timeout_s=300.0, description="notification"):
    seen: list[tuple[dict, dict]] = []

    def _probe():
        seen.extend(_receive_round(ctx, queue_url))
        return [p for p in seen if predicate(p[1])]

    matched = _poll_until(_probe, bool, timeout_s=timeout_s, interval_s=0, description=description)
    return matched[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
