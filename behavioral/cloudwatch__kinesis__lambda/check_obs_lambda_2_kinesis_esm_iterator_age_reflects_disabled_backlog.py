"""obs-lambda-2-kinesis-esm-iterator-age-reflects-disabled-backlog."""
from __future__ import annotations

import datetime as _dt
import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "obs-lambda-2-kinesis-esm-iterator-age-reflects-disabled-backlog"
GROUP = "metrics-emission"
SERVICES = ["cloudwatch", "kinesis", "lambda"]

_HANDLER = 'def lambda_handler(event, context):\n    return {"n": len(event["Records"])}\n'
# D: how long records sit in the shard while the mapping is disabled. 90 s is 1.5 CloudWatch
# periods - an age no fresh record can reach by poller jitter - yet keeps the check near 6 min.
_HOLD_S = 90
_SKEW_S = 5           # client-vs-Kinesis clock tolerance on the lower bound
_FRESH_MAX_MS = 20_000
_BACKLOG, _FRESH = 5, 3


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c6", "concern:data-plane", "concern:e2e",
      "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """Records held while a Kinesis event source mapping is disabled drain with IteratorAge Maximum
    at least the hold time; a later minute of promptly read records reports a far smaller age.
    """
    lam = ctx.client("lambda")
    kin = ctx.client("kinesis")
    cw = ctx.client("cloudwatch")
    t_start = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=2)

    stream, stream_arn = _create_stream(ctx, ctx.unique_name("sim2real-xsvc-obs2ia-"))
    role_arn = _create_role(ctx)
    fn = _create_function(ctx, ctx.unique_name("sim2real-xsvc-obs2ia-"), role_arn)
    esm = _create_mapping(ctx, fn, stream_arn)
    uuid = esm["UUID"]
    _await_state(lam, uuid, "Disabled")

    _put(kin, stream, "held", _BACKLOG)
    t_written = time.monotonic()

    # Hold for D while asserting the mapping stays disabled (and therefore unread).
    while time.monotonic() - t_written < _HOLD_S:
        state = lam.get_event_source_mapping(UUID=uuid)["State"]
        assert state == "Disabled", f"mapping left Disabled during the hold: {state!r}"
        time.sleep(10)
    lam.update_event_source_mapping(UUID=uuid, Enabled=True)
    held_s = time.monotonic() - t_written
    _await_state(lam, uuid, "Enabled")

    backlog = _poll(lambda: _ages(cw, fn, t_start), lambda pts: len(pts) >= 1, 480,
                    "IteratorAge datapoint for the drained backlog")
    first_ts, first_max = backlog[0]
    floor_ms = (held_s - _SKEW_S) * 1000
    assert first_max >= floor_ms, (
        f"first IteratorAge Maximum after enabling was {first_max!r} ms at {first_ts}; records "
        f"were held {held_s:.0f}s while disabled, so it must be >= {floor_ms:.0f} ms"
    )

    # Later period: fresh records written into a minute strictly after the backlog's, read at once.
    t_fresh = max(_dt.datetime.now(_dt.timezone.utc), first_ts + _dt.timedelta(minutes=1))
    t_fresh = (t_fresh + _dt.timedelta(minutes=1)).replace(second=0, microsecond=0) \
        if t_fresh.second or t_fresh.microsecond else t_fresh
    _poll(lambda: _dt.datetime.now(_dt.timezone.utc), lambda now: now >= t_fresh, 130,
          f"clock past fresh-write minute {t_fresh.isoformat()}")
    # A drain that spans minutes shares a minute with fresh records, so a fresh batch is written in
    # every minute from t_fresh on until a minute reports only promptly read records.
    fresh_minutes: set = set()

    def _fresh_points() -> list:
        minute = _dt.datetime.now(_dt.timezone.utc).replace(second=0, microsecond=0)
        if minute >= t_fresh and minute not in fresh_minutes:
            _put(kin, stream, "fresh", _FRESH)
            fresh_minutes.add(minute)
        return [p for p in _ages(cw, fn, t_start) if p[0] >= t_fresh]

    later = _poll(_fresh_points, lambda pts: any(v < _FRESH_MAX_MS for _, v in pts), 480,
                  f"an IteratorAge Maximum below {_FRESH_MAX_MS} ms for promptly read fresh records")
    all_pts = _ages(cw, fn, t_start)
    print(f"[observed] held {held_s:.1f}s; IteratorAge Maximum series {all_pts!r}")
    caught_up = min(v for _, v in later)
    assert caught_up < first_max / 4, (
        f"caught-up IteratorAge {caught_up!r} ms is not far below the backlog's {first_max!r} ms; "
        f"series {all_pts!r}"
    )


def _put(kin: Any, stream: str, tag: str, n: int) -> None:
    resp = kin.put_records(StreamName=stream, Records=[
        {"Data": json.dumps({"phase": tag, "i": i}).encode(), "PartitionKey": f"{tag}-{i}"}
        for i in range(n)])
    assert resp.get("FailedRecordCount", 0) == 0, f"put_records {tag}: {resp!r}"


def _ages(cw: Any, fn: str, start: _dt.datetime) -> list:
    dps = cw.get_metric_statistics(
        Namespace="AWS/Lambda", MetricName="IteratorAge",
        Dimensions=[{"Name": "FunctionName", "Value": fn}],
        StartTime=start, EndTime=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=2),
        Period=60, Statistics=["Maximum"], Unit="Milliseconds",
    )["Datapoints"]
    return sorted((d["Timestamp"], float(d["Maximum"])) for d in dps)




def _poll(probe, pred, timeout_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(5)
    raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")


def _create_stream(ctx: Any, name: str) -> tuple[str, str]:
    kin = ctx.client("kinesis")
    kin.create_stream(StreamName=name, ShardCount=1,
                      StreamModeDetails={"StreamMode": "PROVISIONED"})
    ctx.on_cleanup(lambda: kin.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    kin.get_waiter("stream_exists").wait(StreamName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    kin.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    arn = kin.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


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
        "Action": ["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream",
                   "kinesis:DescribeStreamSummary", "kinesis:ListShards", "kinesis:ListStreams"],
        "Resource": "*"}]}
    iam.put_role_policy(RoleName=name, PolicyName="exec", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="exec"))
    return arn


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


def _create_mapping(ctx: Any, fn_name: str, stream_arn: str) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 120
    while True:
        try:
            esm = lam.create_event_source_mapping(
                FunctionName=fn_name, EventSourceArn=stream_arn, StartingPosition="TRIM_HORIZON",
                BatchSize=100, MaximumBatchingWindowInSeconds=0, Enabled=False)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # IAM propagation: the role's stream permissions are not effective yet.
            if "Cannot access stream" not in str(exc) or time.monotonic() > deadline:
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
