"""xsvc-lambda-1-esm-event-count-metrics-are-opt-in-per-mapping."""
from __future__ import annotations

import datetime as _dt
import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "xsvc-lambda-1-esm-event-count-metrics-are-opt-in-per-mapping"
GROUP = "metrics-emission"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER = 'def lambda_handler(event, context):\n    return {"n": len(event["Records"])}\n'
_FILTER = json.dumps({"dynamodb": {"NewImage": {"keep": {"S": ["yes"]}}}})
_ESM_METRICS = ("PolledEventCount", "InvokedEventCount", "FilteredOutEventCount")
_KEPT, _DROPPED = 4, 1


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """Two DynamoDB-stream mappings process the same records: the one with MetricsConfig EventCount
    publishes PolledEventCount=5, InvokedEventCount=4 and FilteredOutEventCount=1, the one without
    it publishes none of them although its function ran."""
    lam = ctx.client("lambda")
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    t_start = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=2)

    role_arn = _create_stream_role(ctx)
    on_stream = _create_stream_table(ctx, ctx.unique_name("sim2real-xsvc-esmon-"))
    off_stream = _create_stream_table(ctx, ctx.unique_name("sim2real-xsvc-esmoff-"))
    fn_on = _create_function(ctx, ctx.unique_name("sim2real-xsvc-esmon-"), role_arn)
    fn_off = _create_function(ctx, ctx.unique_name("sim2real-xsvc-esmoff-"), role_arn)

    on = _create_mapping(ctx, fn_on, on_stream, metrics=True)
    off = _create_mapping(ctx, fn_off, off_stream, metrics=False)
    assert on.get("MetricsConfig") == {"Metrics": ["EventCount"]}, (
        f"metrics-on mapping MetricsConfig {on.get('MetricsConfig')!r}"
    )
    assert not off.get("MetricsConfig", {}).get("Metrics"), (
        f"metrics-off mapping unexpectedly carries MetricsConfig {off.get('MetricsConfig')!r}"
    )
    _await_enabled(lam, on["UUID"])
    _await_enabled(lam, off["UUID"])

    for table_stream in (on_stream, off_stream):
        table = table_stream[0]
        for i in range(_KEPT):
            ddb.put_item(TableName=table, Item={"pk": {"S": f"keep-{i}"}, "keep": {"S": "yes"}})
        for i in range(_DROPPED):
            ddb.put_item(TableName=table, Item={"pk": {"S": f"drop-{i}"}, "keep": {"S": "no"}})

    want = {"PolledEventCount": _KEPT + _DROPPED, "InvokedEventCount": _KEPT,
            "FilteredOutEventCount": _DROPPED}
    deadline = time.monotonic() + 420
    counts: dict = {}
    off_invocations = (0.0, 0)
    while time.monotonic() < deadline:
        counts = {m: _sum(cw, m, "EventSourceMappingUUID", on["UUID"], t_start) for m in _ESM_METRICS}
        off_invocations = _sum(cw, "Invocations", "FunctionName", fn_off, t_start)
        if all(counts[m][0] >= want[m] for m in want) and off_invocations[1] >= 1:
            break
        time.sleep(15)
    else:
        raise AssertionError(
            f"barrier not reached in 420s: metrics-on counts {counts!r} (want {want!r}), "
            f"metrics-off function Invocations {off_invocations!r}"
        )
    for m, expected in want.items():
        assert counts[m][0] == expected, (
            f"{m} for the metrics-on mapping summed to {counts[m][0]!r}, expected exactly {expected} "
            f"({_KEPT} kept + {_DROPPED} filtered record(s)); all: {counts!r}"
        )
    assert off_invocations[0] >= 1, (
        f"metrics-off function never ran, so its absence proves nothing: {off_invocations!r}"
    )

    off_counts = {m: _sum(cw, m, "EventSourceMappingUUID", off["UUID"], t_start) for m in _ESM_METRICS}
    assert all(n == 0 for _, n in off_counts.values()), (
        f"mapping without MetricsConfig published ESM datapoints {off_counts!r}; they are opt-in"
    )


def _sum(cw: Any, metric: str, dim: str, value: str, start: _dt.datetime) -> tuple[float, int]:
    dps = cw.get_metric_statistics(
        Namespace="AWS/Lambda", MetricName=metric, Dimensions=[{"Name": dim, "Value": value}],
        StartTime=start, EndTime=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=2),
        Period=60, Statistics=["Sum"],
    )["Datapoints"]
    return float(sum(d["Sum"] for d in dps)), len(dps)


def _create_stream_role(ctx: Any) -> str:
    # Inline policy, deliberately WITHOUT logs:CreateLogGroup: the check owns the log group
    # (see _own_log_group), so a log flush buffered past delete_function cannot recreate it.
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-esmrole-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/sim2real-xsvc-*:*"}, {
        "Effect": "Allow", "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator",
                   "dynamodb:ListStreams"], "Resource": "*"}]}
    iam.put_role_policy(RoleName=name, PolicyName="exec", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="exec"))
    return arn


def _create_stream_table(ctx: Any, name: str) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    stream = ddb.create_table(
        TableName=name, BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TableDescription"]["LatestStreamArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, stream


def _own_log_group(ctx: Any, fn_name: str) -> None:
    # The check creates the function's log group itself, BEFORE the function, and the role
    # cannot create one. LIFO cleanup deletes it after delete_function and before the role,
    # so a late buffered flush gets AccessDenied instead of resurrecting the group.
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
            lam.create_function(FunctionName=name, Runtime="python3.13", Role=role_arn,
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


def _create_mapping(ctx: Any, fn_name: str, table_stream: tuple[str, str], metrics: bool) -> dict:
    lam = ctx.client("lambda")
    kwargs: dict = dict(FunctionName=fn_name, EventSourceArn=table_stream[1],
                        StartingPosition="TRIM_HORIZON", BatchSize=10,
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
            # IAM propagation: the role's stream permissions are not effective yet.
            if time.monotonic() > deadline:
                raise
            print(f"[retry] create_event_source_mapping: {exc}")
            time.sleep(5)
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm["UUID"]))
    return esm


def _await_enabled(lam: Any, uuid: str) -> None:
    deadline = time.monotonic() + 120
    state = None
    while time.monotonic() < deadline:
        state = lam.get_event_source_mapping(UUID=uuid)["State"]
        if state == "Enabled":
            return
        time.sleep(3)
    raise AssertionError(f"event source mapping {uuid} stuck in {state!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
