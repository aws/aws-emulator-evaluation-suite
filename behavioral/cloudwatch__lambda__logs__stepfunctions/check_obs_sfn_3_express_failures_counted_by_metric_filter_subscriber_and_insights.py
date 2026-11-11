"""obs-sfn-3-express-failures-counted-by-metric-filter-subscriber-and-insights."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-sfn-3-express-failures-counted-by-metric-filter-subscriber-and-insights"
GROUP = "observability"
SERVICES = ["cloudwatch", "lambda", "logs", "stepfunctions"]

_N_OK = 2
_N_FAIL = 3
_READY_BUDGET_S = 360.0
_DELIVERY_BUDGET_S = 420.0
#: How long a reading that reached its expected count must then hold unchanged.
_STABLE_WINDOW_S = 10
_MARK = "SIM2REAL_SUB"
_INSIGHTS = 'filter type="ExecutionFailed" | stats count(*) by execution_arn'


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:metrics",
    "concern:eventing",
    "concern:data-plane",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """After 2 successful and 3 failing EXPRESS executions, a metric filter sums 3, a subscription
    filter delivers exactly the 3 FailStateEntered events, and Insights returns 3 rows of count 1;
    no successful execution's ARN appears on any surface.
    """
    sfn = ctx.client("stepfunctions")
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    window_start = datetime.now(timezone.utc) - timedelta(minutes=5)

    group = ctx.unique_name("/aws/vendedlogs/states/sim2real-xsvc-obssfn3-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": "cloudwatch__lambda__logs__sfn"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"

    # ---- consumers first: filters apply only to events ingested after they exist --------------- #
    namespace = ctx.unique_name("Sim2Real/obssfn3-")
    metric_name = "ExpressExecutionFailed"
    logs.put_metric_filter(
        logGroupName=group,
        filterName="express-failed",
        filterPattern='{$.type = "ExecutionFailed"}',
        metricTransformations=[
            {"metricName": metric_name, "metricNamespace": namespace, "metricValue": "1"}
        ],
    )
    ctx.on_cleanup(lambda: logs.delete_metric_filter(logGroupName=group, filterName="express-failed"))

    fn_name, fn_arn, fn_group = _subscriber_lambda(ctx)
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId="cwlogs-invoke",
        Action="lambda:InvokeFunction",
        Principal="logs.amazonaws.com",
        SourceArn=f"{group_arn}:*",
        SourceAccount=account,
    )
    _retry(
        lambda: logs.put_subscription_filter(
            logGroupName=group,
            filterName="fail-state-entered",
            filterPattern='{$.type = "FailStateEntered"}',
            destinationArn=fn_arn,
        ),
        code="InvalidParameterException",
        budget_s=90.0,
        description="PutSubscriptionFilter while the fresh logs.amazonaws.com invoke grant propagates",
    )
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName="fail-state-entered")
    )

    machine = _express_machine(ctx, sfn, _states_role(ctx), f"{group_arn}:*")

    # ---- readiness barrier: successful executions until one is delivered ----------------------- #
    # A new EXPRESS machine drops (not delays) executions started in its first seconds, so warm up
    # with SUCCESSFUL executions, which must reach none of the failure surfaces.
    warmups = _await_delivery_ready(ctx, sfn, logs, machine, group)

    # ---- the data plane: 2 successful + 3 failing sync executions ------------------------------ #
    ok_arns, fail_arns = [], []
    for ok in [True] * _N_OK + [False] * _N_FAIL:
        resp = sfn.start_sync_execution(stateMachineArn=machine, input=json.dumps({"ok": ok}))
        want = "SUCCEEDED" if ok else "FAILED"
        assert resp["status"] == want, (
            f"sync execution with ok={ok} ended {resp['status']!r} ({resp.get('error')!r}), "
            f"expected {want!r}"
        )
        if not ok:
            assert resp.get("error") == "Sim2RealDeliberateFailure", (
                f"failing execution reports error {resp.get('error')!r}, expected the Fail state's "
                f"'Sim2RealDeliberateFailure'"
            )
        (ok_arns if ok else fail_arns).append(resp["executionArn"])
    not_failed = set(ok_arns) | set(warmups)

    # ---- surface 0: the log group itself carries the history for every measured execution ----- #
    events = _poll_until(
        lambda: _log_events(logs, group),
        lambda evs: {e.get("execution_arn") for e in evs if e.get("type") == "ExecutionFailed"}
        >= set(fail_arns)
        and {e.get("execution_arn") for e in evs if e.get("type") == "ExecutionSucceeded"}
        >= set(ok_arns),
        timeout_s=_budget_s(ctx, _DELIVERY_BUDGET_S),
        interval_s=2.0, ctx=ctx,
        description="ExecutionFailed x3 and ExecutionSucceeded x2 reaching the express log group",
    )
    leaked_fail = sorted(
        {e.get("execution_arn") for e in events if e.get("type") in {"ExecutionFailed",
                                                                     "FailStateEntered"}}
        & not_failed
    )
    assert leaked_fail == [], (
        f"successful executions {leaked_fail!r} logged a failure event type in {group}"
    )

    # ---- surface 1: metric filter -> custom metric Sum == 3 ------------------------------------ #
    def metric_sum():
        dps = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum"],
        )["Datapoints"]
        return float(sum(d["Sum"] for d in dps)) if dps else None

    total = _poll_until_settled(
        ctx,
        metric_sum,
        reached=lambda v: v >= float(_N_FAIL),
        window_s=_STABLE_WINDOW_S,
        timeout_s=_DELIVERY_BUDGET_S,
        description=f"metric-filter metric {namespace}/{metric_name}",
    )
    assert total == float(_N_FAIL), (
        f"the metric filter {{$.type = \"ExecutionFailed\"}} published Sum {total!r} to "
        f"{namespace}/{metric_name}; exactly {_N_FAIL} executions failed and "
        f"{len(not_failed)} succeeded, so it must be {float(_N_FAIL)!r}"
    )

    # ---- surface 2: subscription filter -> Lambda got exactly the 3 FailStateEntered events ---- #
    received = _poll_until_settled(
        ctx,
        lambda: _subscriber_records(logs, fn_group) or None,
        reached=lambda recs: len({r["id"] for r in recs}) >= _N_FAIL,
        window_s=_STABLE_WINDOW_S,
        timeout_s=_DELIVERY_BUDGET_S,
        description=f"subscriber {fn_name} receiving FailStateEntered events",
    )
    # Subscription delivery may retry an invocation, so identity is the CloudWatch Logs event id.
    by_id = {r["id"]: r for r in received}
    assert len(by_id) == _N_FAIL, (
        f"the subscriber received {len(by_id)} distinct log events {sorted(by_id)!r}; exactly "
        f"{_N_FAIL} FailStateEntered events exist (one per failed execution)"
    )
    assert {r["type"] for r in by_id.values()} == {"FailStateEntered"}, (
        f"the subscriber received event types {sorted({r['type'] for r in by_id.values()})!r}; "
        f"the filter pattern selects FailStateEntered only"
    )
    assert sorted(r["execution_arn"] for r in by_id.values()) == sorted(fail_arns), (
        f"the subscriber's execution_arns {sorted(r['execution_arn'] for r in by_id.values())!r} "
        f"must be exactly the failed executions {sorted(fail_arns)!r}"
    )
    assert {r["group"] for r in by_id.values()} == {group} and all(
        r["filters"] == ["fail-state-entered"] for r in by_id.values()
    ), f"subscriber envelopes name the wrong source: {list(by_id.values())!r}"

    # ---- surface 3: Logs Insights over the same events ----------------------------------------- #
    rows = _poll_until(
        lambda: _insights(logs, group, window_start),
        lambda r: r is not None and len(r) >= _N_FAIL,
        timeout_s=_budget_s(ctx, _DELIVERY_BUDGET_S),
        interval_s=2.0, ctx=ctx,
        description=f"Insights query {_INSIGHTS!r} returning {_N_FAIL} rows",
    )
    assert rows == {arn: "1" for arn in fail_arns}, (
        f"Insights {_INSIGHTS!r} returned {rows!r}; expected one row of count 1 for each failed "
        f"execution {sorted(fail_arns)!r} and no row for any successful one"
    )


_TAG = "cloudwatch__lambda__logs__sfn"
_DEFINITION = json.dumps(
    {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.ok", "BooleanEquals": True, "Next": "Fine"}],
                "Default": "Boom",
            },
            "Fine": {"Type": "Pass", "End": True},
            "Boom": {
                "Type": "Fail",
                "Error": "Sim2RealDeliberateFailure",
                "Cause": "obs-sfn-3 express failure",
            },
        },
    }
)
_LOG_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    "logs:CreateLogStream", "logs:PutLogEvents",
]
_SUBSCRIBER_CODE = f'''
import base64, gzip, json

def handler(event, context):
    data = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    if data.get("messageType") != "DATA_MESSAGE":
        return
    for le in data["logEvents"]:
        msg = json.loads(le["message"])
        print("{_MARK} " + json.dumps({{
            "id": le["id"], "type": msg.get("type"), "execution_arn": msg.get("execution_arn"),
            "group": data["logGroup"], "filters": data["subscriptionFilters"]}}))
'''


def _role(ctx, service: str, label: str, actions: list[str], resource: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-xsvc-obssfn3-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": service},
                     "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Description=f"sim2real {_TAG} {label}",
        Tags=[{"Key": "sim2real", "Value": _TAG}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


def _states_role(ctx) -> str:
    return _role(ctx, "states.amazonaws.com", "sfn", _LOG_ACTIONS, "*")[1]


def _subscriber_lambda(ctx) -> tuple[str, str, str]:
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fn_name = ctx.unique_name("sim2real-xsvc-obssfn3-sub-")
    fn_group = f"/aws/lambda/{fn_name}"
    # Registered BEFORE the function exists so LIFO reaps it AFTER delete_function: a buffered
    # invocation log can flush after the delete and recreate the group.
    ctx.on_cleanup(lambda: _reap_log_group(logs, fn_group))
    logs.create_log_group(logGroupName=fn_group, tags={"sim2real": _TAG})
    _, role_arn = _role(
        ctx, "lambda.amazonaws.com", "fn", ["logs:CreateLogStream", "logs:PutLogEvents"],
        f"arn:aws:logs:{ctx.region}:{account}:log-group:{fn_group}:*",
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _SUBSCRIBER_CODE)
    fn_arn = _retry(
        lambda: lam.create_function(
            FunctionName=fn_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": buf.getvalue()},
            Timeout=30,
            Tags={"sim2real": _TAG},
        )["FunctionArn"],
        code="InvalidParameterValueException",
        budget_s=90.0,
        description="CreateFunction while the fresh Lambda role becomes assumable",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name, fn_arn, fn_group


def _reap_log_group(logs, name: str) -> None:
    """Delete, then watch for a late flush recreating the group; bounded, and loud if it never
    converges rather than hanging."""
    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(10.0)
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if not any(g["logGroupName"] == name for g in groups):
            return
    raise RuntimeError(f"log group {name} kept reappearing after delete")


def _express_machine(ctx, sfn, role_arn: str, log_group_arn: str) -> str:
    name = ctx.unique_name("sim2real-xsvc-obssfn3-x-")[:80]
    arn = _retry(
        lambda: sfn.create_state_machine(
            name=name,
            definition=_DEFINITION,
            roleArn=role_arn,
            type="EXPRESS",
            loggingConfiguration={
                "level": "ALL",
                "includeExecutionData": True,
                "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": log_group_arn}}],
            },
            tags=[{"key": "sim2real", "value": _TAG}],
        )["stateMachineArn"],
        code="AccessDeniedException",
        budget_s=120.0,
        description="CreateStateMachine while the fresh states role becomes assumable",
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _await_delivery_ready(ctx, sfn, logs, machine: str, group: str) -> list[str]:
    """Start SUCCESSFUL executions until one of them is delivered to the group; return all of
    their ARNs (none may ever reach a failure surface)."""
    deadline = time.monotonic() + _budget_s(ctx, _READY_BUDGET_S)
    started: list[str] = []
    while time.monotonic() < deadline:
        resp = sfn.start_sync_execution(stateMachineArn=machine, input=json.dumps({"ok": True}))
        assert resp["status"] == "SUCCEEDED", f"warm-up execution ended {resp['status']!r}"
        started.append(resp["executionArn"])
        # Each warm-up gets up to 15 s to be delivered before the next one starts.
        next_start = min(deadline, time.monotonic() + 15.0)
        while time.monotonic() < next_start:
            time.sleep(2.0)
            delivered = {e.get("execution_arn") for e in _log_events(logs, group)}
            if delivered & set(started):
                return started
    if _budget_spent(ctx):
        raise TimeoutError(f"a warm-up execution reaching {group}: the run budget ended first; not graded")
    raise AssertionError(
        f"the EXPRESS machine's level-ALL log delivery never delivered any of {len(started)} "
        f"successful warm-up executions to {group} within {_READY_BUDGET_S}s"
    )


def _log_events(logs, group: str) -> list[dict]:
    out: list[dict] = []
    for page in logs.get_paginator("filter_log_events").paginate(logGroupName=group):
        out.extend(json.loads(e["message"]) for e in page["events"])
    return out


def _subscriber_records(logs, fn_group: str) -> list[dict]:
    out: list[dict] = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=fn_group, filterPattern=f'"{_MARK}"'
        ):
            for e in page["events"]:
                line = e["message"].strip()
                out.append(json.loads(line[line.index(_MARK) + len(_MARK):]))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return sorted(out, key=lambda r: r["id"])


def _insights(logs, group: str, start: datetime):
    qid = logs.start_query(
        logGroupName=group,
        startTime=int(start.timestamp()),
        endTime=int(time.time()) + 300,
        queryString=_INSIGHTS,
    )["queryId"]
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        r = logs.get_query_results(queryId=qid)
        if r["status"] == "Complete":
            rows = {}
            for row in r["results"]:
                cells = {c["field"]: c["value"] for c in row}
                rows[cells.get("execution_arn")] = cells.get("count(*)")
            return rows
        assert r["status"] in {"Scheduled", "Running"}, f"Insights query ended {r['status']!r}"
        time.sleep(2.0)
    raise AssertionError(f"Insights query {qid} did not complete within 120s")


def _retry(call, *, code: str, budget_s: float, description: str):
    """Retry ONLY the one propagation refusal named, bounded by a deadline that raises."""
    deadline = time.monotonic() + budget_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return call()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != code:
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(f"{description}: still refused after {budget_s}s; last {last!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until_settled(ctx, probe, *, reached, window_s, timeout_s, interval_s=2.0,
                        description="reading"):
    """Return the first reading that satisfies `reached` and then holds unchanged for window_s."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if last is None or not reached(last):
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
        elif now - anchor_t >= window_s:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} never reached its expected value and held it for {window_s}s within "
        f"{timeout_s}s; last reading was {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
