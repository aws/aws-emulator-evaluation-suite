"""alarm-log-metric-chain-deleted-filter-stops-counting-but-keeps-datapoints."""

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

CHECK = "alarm-log-metric-chain-deleted-filter-stops-counting-but-keeps-datapoints"

GROUP = "metric-filter"

SERVICES = ["cloudwatch", "lambda", "logs", "sns", "sqs"]

_N = 3


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deleting a metric filter stops new datapoints on its metric but keeps those it already
    produced; a control filter with the same pattern counts the later lines exactly.
    """
    window_start = datetime.now(timezone.utc) - timedelta(minutes=10)
    logs = ctx.client("logs")
    src = _lambda_source(ctx)
    namespace = ctx.unique_name("Sim2Real/AlarmChain/")
    doomed_metric, control_metric = "DoomedLines", "ControlLines"
    pattern = _pattern("ERROR", src["marker"])
    doomed = _xname(ctx, "mf-doomed")
    control = _xname(ctx, "mf-control")
    _put_filter(ctx, src["group"], doomed, pattern, namespace, doomed_metric)
    _put_filter(ctx, src["group"], control, pattern, namespace, control_metric)
    _warm(ctx, src, namespace, doomed_metric, "ERROR", window_start)
    _warm(ctx, src, namespace, control_metric, "ERROR", window_start)

    # ---- both filters count the `pre` lines exactly ----
    for seq in range(_N):
        _invoke(ctx, src, "ERROR", "pre", seq)
    _await_lines(ctx, src, "pre", _N)
    for m in (doomed_metric, control_metric):
        total = sum(dp["Sum"] for dp in _await_metric_sum(ctx, namespace, m, "pre", window_start, _N))
        assert total == float(_N), f"{m} Batch=pre Sum {total!r}, expected {_N}"

    # ---- break exactly one link: delete the doomed filter ----
    logs.delete_metric_filter(logGroupName=src["group"], filterName=doomed)
    err = _error(lambda: logs.delete_metric_filter(logGroupName=src["group"], filterName=doomed))
    expected = ("ResourceNotFoundException", "The specified metric filter does not exist.")
    assert err == expected, f"deleting the filter twice: {err!r}, expected {expected!r}"
    names = [f["filterName"] for f in logs.describe_metric_filters(logGroupName=src["group"])["metricFilters"]]
    assert names == [control], f"filters on the group after the delete: {names!r}"

    for seq in range(_N):
        _invoke(ctx, src, "ERROR", "post", seq)
    post_lines = _await_lines(ctx, src, "post", _N)
    assert all(e["parsed"]["level"] == "ERROR" for e in post_lines), post_lines

    # Barrier: the surviving control filter counts every post line.
    ctrl = sum(dp["Sum"] for dp in _await_metric_sum(ctx, namespace, control_metric, "post", window_start, _N))
    assert ctrl == float(_N), f"control filter Batch=post Sum {ctrl!r}, expected {_N}"

    # ---- effect absent: no new datapoints from the deleted filter ----
    post_dps = _metric_datapoints(ctx, namespace, doomed_metric, "post", window_start)
    assert post_dps == [], f"a deleted filter must produce no datapoints, Batch=post has {post_dps!r}"

    # ---- what it already produced stays: metrics belong to CloudWatch, not the filter ----
    kept = sum(dp["Sum"] for dp in _metric_datapoints(ctx, namespace, doomed_metric, "pre", window_start))
    assert kept == float(_N), (
        f"datapoints the filter emitted before deletion must survive it: Batch=pre Sum {kept!r}, expected {_N}"
    )


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, ctx, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not observed within the {timeout_s}s poll budget. Last: {last!r}")


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
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
    deadline = time.monotonic() + _budget_s(ctx, 60)
    while True:  # IAM propagation: the new role is not yet assumable by Lambda
        try:
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("create_function accepting the new role: the run budget ended "
                                       "first; not graded") from exc
                raise AssertionError(f"create_function never accepted the new role: {exc!r}")
            time.sleep(2)
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
        lambda s: s in ("Active", "Failed"), ctx=ctx, timeout_s=180, interval_s=2,
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

    _poll_until(_prime_and_read, lambda ev: len(ev) >= 1, ctx=ctx, timeout_s=300, interval_s=2,
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
        lambda: _read_lines(ctx, src, batch), lambda ev: len(ev) >= n, ctx=ctx, timeout_s=300,
        interval_s=2, description=f"{n} '{batch}' lines in {src['group']}",
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
        lambda dps: sum(dp["Sum"] for dp in dps) >= n, ctx=ctx, timeout_s=420, interval_s=2,
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

    _poll_until(_emit_and_read, lambda dps: sum(dp["Sum"] for dp in dps) >= 1, ctx=ctx,
                timeout_s=420, interval_s=3, description=f"filter {namespace}/{metric} counting a {level} {batch} line")


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
        ctx=ctx, timeout_s=timeout_s, interval_s=2,
        description=f"alarm {name} evaluating to {state}",
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

    matched = _poll_until(
        _probe, bool, ctx=ctx, timeout_s=timeout_s, interval_s=0, description=description
    )
    return matched[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
