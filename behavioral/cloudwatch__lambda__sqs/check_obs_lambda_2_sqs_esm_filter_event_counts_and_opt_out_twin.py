"""obs-lambda-2-sqs-esm-filter-event-counts-and-opt-out-twin."""
from __future__ import annotations

import datetime as _dt
import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "obs-lambda-2-sqs-esm-filter-event-counts-and-opt-out-twin"
GROUP = "metrics-emission"
SERVICES = ["cloudwatch", "lambda", "sqs"]

_HANDLER = 'def lambda_handler(event, context):\n    return {"n": len(event["Records"])}\n'
_FILTER = json.dumps({"body": {"kind": ["keep"]}})
_ESM_METRICS = ("PolledEventCount", "InvokedEventCount", "FilteredOutEventCount", "DeletedEventCount")
_KEPT, _DROPPED = 4, 3


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """An SQS mapping with a body filter and MetricsConfig EventCount publishes exact per-mapping counts
    under EventSourceMappingUUID alone (FilteredOut 3, Deleted 7, every message leaves the queue);
    a twin mapping without MetricsConfig publishes none although its function ran.
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")
    t_start = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=2)

    role_arn = _create_role(ctx)
    q_on = _create_queue(ctx, ctx.unique_name("sim2real-xsvc-obs2on-"))
    q_off = _create_queue(ctx, ctx.unique_name("sim2real-xsvc-obs2off-"))
    fn_on = _create_function(ctx, ctx.unique_name("sim2real-xsvc-obs2on-"), role_arn)
    fn_off = _create_function(ctx, ctx.unique_name("sim2real-xsvc-obs2off-"), role_arn)

    on = _create_mapping(ctx, fn_on, q_on[1], metrics=True)
    off = _create_mapping(ctx, fn_off, q_off[1], metrics=False)
    assert on.get("MetricsConfig") == {"Metrics": ["EventCount"]}, (
        f"metrics-on mapping MetricsConfig {on.get('MetricsConfig')!r}"
    )
    assert not off.get("MetricsConfig", {}).get("Metrics"), (
        f"metrics-off mapping unexpectedly carries MetricsConfig {off.get('MetricsConfig')!r}"
    )
    _await_state(lam, on["UUID"], "Enabled")
    _await_state(lam, off["UUID"], "Enabled")

    for url, _ in (q_on, q_off):
        entries = [{"Id": f"k{i}", "MessageBody": json.dumps({"kind": "keep", "i": i})}
                   for i in range(_KEPT)]
        entries += [{"Id": f"d{i}", "MessageBody": json.dumps({"kind": "drop", "i": i})}
                    for i in range(_DROPPED)]
        resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
        assert not resp.get("Failed") and len(resp.get("Successful", [])) == _KEPT + _DROPPED, (
            f"send_message_batch did not accept all {_KEPT + _DROPPED} messages: {resp!r}"
        )

    # Kept AND filtered messages both leave the queue: a filter drop is a delete.
    for url, _ in (q_on, q_off):
        depth = _poll(lambda u=url: _depth(sqs, u), lambda d: d == (0, 0), 180,
                      f"queue {url} drained")
        assert depth == (0, 0), f"queue {url} still holds (visible, in-flight) {depth!r}"

    floor = {"PolledEventCount": _KEPT + _DROPPED, "InvokedEventCount": _KEPT,
             "FilteredOutEventCount": _DROPPED, "DeletedEventCount": _KEPT}
    deadline = time.monotonic() + 480
    counts: dict = {}
    off_inv: tuple = (0.0, 0, set())
    while time.monotonic() < deadline:
        counts = {m: _sum(cw, m, "EventSourceMappingUUID", on["UUID"], t_start) for m in _ESM_METRICS}
        off_inv = _sum(cw, "Invocations", "FunctionName", fn_off, t_start)
        if all(counts[m][0] >= floor[m] for m in floor) and off_inv[1] >= 1:
            break
        time.sleep(2)
    else:
        raise AssertionError(
            f"barrier not reached in 480s: metrics-on counts {counts!r} (floor {floor!r}), "
            f"metrics-off function Invocations {off_inv!r}"
        )
    # Re-read until one value holds for a window, so a late datapoint cannot hide an over-count.
    counts = _stable(lambda: {m: _sum(cw, m, "EventSourceMappingUUID", on["UUID"], t_start)[:2]
                              for m in _ESM_METRICS}, counts)
    counts = {m: _sum(cw, m, "EventSourceMappingUUID", on["UUID"], t_start) for m in _ESM_METRICS}
    print(f"[observed] metrics-on mapping {on['UUID']} counts {counts!r}")

    assert counts["FilteredOutEventCount"][0] == _DROPPED, (
        f"FilteredOutEventCount summed to {counts['FilteredOutEventCount'][0]!r}, expected exactly "
        f"{_DROPPED} non-matching message(s); all: {counts!r}"
    )
    # Measured on real AWS: for SQS the poller deletes FILTERED messages too, and counts them,
    # so DeletedEventCount is kept + filtered (7), not kept alone (4).
    assert counts["DeletedEventCount"][0] == _KEPT + _DROPPED, (
        f"DeletedEventCount summed to {counts['DeletedEventCount'][0]!r}, expected exactly "
        f"{_KEPT + _DROPPED} ({_KEPT} invoked-then-deleted + {_DROPPED} filtered-then-deleted); "
        f"all: {counts!r}"
    )
    assert counts["InvokedEventCount"][0] >= _KEPT, (
        f"InvokedEventCount summed to {counts['InvokedEventCount'][0]!r}, below the {_KEPT} "
        f"matching messages; all: {counts!r}"
    )
    assert counts["PolledEventCount"][0] >= _KEPT + _DROPPED, (
        f"PolledEventCount summed to {counts['PolledEventCount'][0]!r}, below the "
        f"{_KEPT + _DROPPED} messages sent; all: {counts!r}"
    )
    assert counts["PolledEventCount"][2] == {"Count"}, (
        f"PolledEventCount datapoints carry units {counts['PolledEventCount'][2]!r}, expected Count"
    )
    assert off_inv[0] >= 1, f"metrics-off function never ran, so its absence proves nothing: {off_inv!r}"

    # The ESM counts are dimensioned by EventSourceMappingUUID ALONE (observed via
    # list_metrics); nothing is published under the function's name.
    by_fn = {m: _sum(cw, m, "FunctionName", fn_on, t_start)[1] for m in _ESM_METRICS}
    assert all(n == 0 for n in by_fn.values()), (
        f"ESM counts also published under FunctionName={fn_on}: datapoints {by_fn!r}"
    )

    off_counts = {m: _sum(cw, m, "EventSourceMappingUUID", off["UUID"], t_start) for m in _ESM_METRICS}
    assert all(n == 0 for _, n, _u in off_counts.values()), (
        f"mapping without MetricsConfig published ESM datapoints {off_counts!r}; they are opt-in"
    )


# ===== helpers =====


def _sum(cw: Any, metric: str, dim: str, value: str, start: _dt.datetime) -> tuple:
    dps = cw.get_metric_statistics(
        Namespace="AWS/Lambda", MetricName=metric, Dimensions=[{"Name": dim, "Value": value}],
        StartTime=start, EndTime=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=2),
        Period=60, Statistics=["Sum"],
    )["Datapoints"]
    return float(sum(d["Sum"] for d in dps)), len(dps), {d.get("Unit") for d in dps}


def _stable(read, first: dict, window_s: float = 20.0, timeout_s: float = 150) -> dict:
    prev, since = {k: v[:2] for k, v in first.items()}, time.monotonic()
    deadline = since + timeout_s
    while time.monotonic() < deadline:
        time.sleep(2)
        cur = read()
        if cur != prev:
            prev, since = cur, time.monotonic()
        elif time.monotonic() - since >= window_s:
            return cur
    raise AssertionError(f"ESM counts still moving after {timeout_s}s; last {prev!r}")


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
