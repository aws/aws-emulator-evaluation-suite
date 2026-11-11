"""obs-lambda-2-sqs-esm-cleared-metrics-config-freezes-event-counts."""
from __future__ import annotations

import datetime as _dt
import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "obs-lambda-2-sqs-esm-cleared-metrics-config-freezes-event-counts"
GROUP = "metrics-emission"
SERVICES = ["cloudwatch", "lambda", "sqs"]

_HANDLER = 'def lambda_handler(event, context):\n    return {"n": len(event["Records"])}\n'
_FILTER = json.dumps({"body": {"kind": ["keep"]}})
_ESM_METRICS = ("PolledEventCount", "InvokedEventCount", "FilteredOutEventCount", "DeletedEventCount")
_A, _B = 3, 4
_COUNTED = ("PolledEventCount", "InvokedEventCount", "DeletedEventCount")


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:eventing", "concern:metrics", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx: Any) -> None:
    """Clearing an SQS ESM's MetricsConfig (Metrics=[]) freezes its per-mapping event counts while it
    keeps processing: later messages add no EventSourceMappingUUID datapoint and totals stay put.
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")
    t_start = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=2)

    role_arn = _create_role(ctx)
    url, arn = _create_queue(ctx, ctx.unique_name("sim2real-xsvc-obs2frz-"))
    fn = _create_function(ctx, ctx.unique_name("sim2real-xsvc-obs2frz-"), role_arn)
    esm = _create_mapping(ctx, fn, arn, metrics=True)
    uuid = esm["UUID"]
    _await_state(lam, uuid, "Enabled")

    def series() -> dict:
        return {m: _series(cw, m, uuid, t_start) for m in _ESM_METRICS}

    # First batch: counted.
    _send(sqs, url, "a", _A)
    _poll(lambda: _depth(sqs, url), lambda d: d == (0, 0), 180, "phase A drained")
    _poll(series, lambda s: all(_total(s, m) >= _A for m in _COUNTED), 480,
          "phase A Polled/Invoked/Deleted counts")
    before = _stable(series)
    assert _total(before, "PolledEventCount") == _A and _total(before, "InvokedEventCount") == _A, (
        f"phase A: expected Polled=Invoked={_A}, series {before!r}"
    )

    # Positive control for the absence below: an ENABLED mapping publishes a 0-valued
    # PolledEventCount datapoint for an idle minute, so an empty window later is suppression,
    # not ingestion lag.
    before = _poll(series, lambda s: any(v == 0.0 for _, v in s["PolledEventCount"]), 240,
                   "an idle-minute PolledEventCount datapoint while metrics are enabled")
    assert all(_total(before, m) == _A for m in _COUNTED), f"phase A totals moved: {before!r}"

    # Freeze: Metrics=[] is accepted, read back empty, and the mapping keeps running.
    upd = lam.update_event_source_mapping(UUID=uuid, MetricsConfig={"Metrics": []})
    assert not upd.get("MetricsConfig", {}).get("Metrics"), (
        f"update to Metrics=[] returned MetricsConfig {upd.get('MetricsConfig')!r}"
    )
    _await_state(lam, uuid, "Enabled")
    stored = lam.get_event_source_mapping(UUID=uuid)
    assert not stored.get("MetricsConfig", {}).get("Metrics"), (
        f"Metrics=[] not persisted; read back {stored.get('MetricsConfig')!r}"
    )

    # Second batch: processed but must not be counted. AWS publishes exactly one more 0-valued
    # datapoint in the minute after the update, then goes silent, so the frozen window opens at
    # the SECOND minute boundary after the update settled.
    t_b = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=2)).replace(
        second=0, microsecond=0)
    _poll(lambda: _dt.datetime.now(_dt.timezone.utc), lambda now: now >= t_b, 135,
          f"clock past the frozen-window start {t_b.isoformat()}")
    _send(sqs, url, "b", _B)
    _poll(lambda: _depth(sqs, url), lambda d: d == (0, 0), 180, "phase B drained")
    # The function's own Invocations datapoint bounds when a leaked ESM count would have appeared.
    inv = _poll(lambda: _invocations_since(cw, fn, t_start, t_b), lambda n: n >= 1, 480,
                "function Invocations datapoint for phase B")
    assert inv >= 1, f"no Invocations datapoint at/after {t_b.isoformat()}: {inv!r}"
    frozen = series()
    leaked = {m: [p for p in pts if p[0] >= t_b.isoformat()] for m, pts in frozen.items()}
    assert not any(leaked.values()), (
        f"MetricsConfig was cleared, yet the ESM published datapoints in the frozen window "
        f"(>= {t_b.isoformat()}): {leaked!r}; full series {frozen!r}"
    )
    for m in _COUNTED:
        assert _total(frozen, m) == _total(before, m), (
            f"{m} moved from {_total(before, m)!r} to {_total(frozen, m)!r} after Metrics=[]; "
            f"the {_B} frozen-phase message(s) were counted"
        )

    print(f"[observed] ESM {uuid} before {before!r} frozen {frozen!r}")


def _send(sqs: Any, url: str, tag: str, n: int) -> None:
    entries = [{"Id": f"{tag}{i}", "MessageBody": json.dumps({"kind": "keep", "phase": tag, "i": i})}
               for i in range(n)]
    resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
    assert not resp.get("Failed") and len(resp.get("Successful", [])) == n, (
        f"send_message_batch phase {tag} did not accept all {n}: {resp!r}"
    )


def _series(cw: Any, metric: str, uuid: str, start: _dt.datetime) -> tuple:
    dps = cw.get_metric_statistics(
        Namespace="AWS/Lambda", MetricName=metric,
        Dimensions=[{"Name": "EventSourceMappingUUID", "Value": uuid}],
        StartTime=start, EndTime=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=2),
        Period=60, Statistics=["Sum"],
    )["Datapoints"]
    return tuple(sorted((d["Timestamp"].isoformat(), float(d["Sum"])) for d in dps))


def _total(series: dict, metric: str) -> float:
    return sum(v for _, v in series[metric])


def _invocations_since(cw: Any, fn: str, start: _dt.datetime, since: _dt.datetime) -> float:
    dps = cw.get_metric_statistics(
        Namespace="AWS/Lambda", MetricName="Invocations",
        Dimensions=[{"Name": "FunctionName", "Value": fn}],
        StartTime=start, EndTime=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=2),
        Period=60, Statistics=["Sum"],
    )["Datapoints"]
    return float(sum(d["Sum"] for d in dps if d["Timestamp"] >= since))


def _stable(read, timeout_s: float = 150) -> dict:
    prev = read()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        time.sleep(20)
        cur = read()
        if cur == prev:
            return cur
        prev = cur
    raise AssertionError(f"ESM series still moving after {timeout_s}s; last {prev!r}")


def _poll(probe, pred, timeout_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(5)
    raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")


def _depth(sqs: Any, url: str) -> tuple[int, int]:
    a = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return int(a["ApproximateNumberOfMessages"]), int(a["ApproximateNumberOfMessagesNotVisible"])


def _create_role(ctx: Any) -> str:
    # Inline policy, deliberately WITHOUT logs:CreateLogGroup: the check owns the log group
    # (see _own_log_group), so a log flush buffered past delete_function cannot recreate it.
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-obs2role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/sim2real-xsvc-*:*"}, {
        "Effect": "Allow",
        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
        "Resource": "*"}]}
    iam.put_role_policy(RoleName=name, PolicyName="exec", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="exec"))
    return arn


def _create_queue(ctx: Any, name: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "60"},
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _own_log_group(ctx: Any, fn_name: str) -> None:
    # Created BEFORE the function, and the role cannot create one. LIFO cleanup deletes it
    # after delete_function, so a late buffered flush gets AccessDenied instead of
    # resurrecting the group; the reap still loops in case one lands mid-delete.
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})

    def _reap() -> None:
        for _ in range(6):
            try:
                logs.delete_log_group(logGroupName=group)
            except logs.exceptions.ResourceNotFoundException:
                pass
            time.sleep(5)
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
            if not any(g["logGroupName"] == group for g in found):
                return
        raise RuntimeError(f"log group {group} kept reappearing")

    ctx.on_cleanup(_reap)


def _create_function(ctx: Any, name: str, role_arn: str) -> str:
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _HANDLER)
    _own_log_group(ctx, name)
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn,
                                Handler="lambda_function.lambda_handler",
                                Code={"ZipFile": buf.getvalue()}, Timeout=30,
                                Tags={"sim2real": CHECK})
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # IAM propagation: the new role is not yet assumable by Lambda.
            if "cannot be assumed" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _create_mapping(ctx: Any, fn_name: str, queue_arn: str, metrics: bool) -> dict:
    lam = ctx.client("lambda")
    kwargs: dict = dict(FunctionName=fn_name, EventSourceArn=queue_arn, BatchSize=10,
                        MaximumBatchingWindowInSeconds=1,
                        FilterCriteria={"Filters": [{"Pattern": _FILTER}]})
    if metrics:
        kwargs["MetricsConfig"] = {"Metrics": ["EventCount"]}
    deadline = time.monotonic() + 120
    while True:
        try:
            esm = lam.create_event_source_mapping(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # IAM propagation: the role's queue permissions are not effective yet.
            if time.monotonic() > deadline:
                raise
            print(f"[retry] create_event_source_mapping: {exc}")
            time.sleep(5)
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm["UUID"]))
    return esm


def _await_state(lam: Any, uuid: str, want: str) -> None:
    deadline = time.monotonic() + 120
    state = None
    while time.monotonic() < deadline:
        state = lam.get_event_source_mapping(UUID=uuid)["State"]
        if state == want:
            return
        time.sleep(3)
    raise AssertionError(f"event source mapping {uuid} stuck in {state!r}, wanted {want!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
