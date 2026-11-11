"""obs-sfn-3-express-billed-metrics-equal-summed-billing-details-standard-twin-has-none."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-sfn-3-express-billed-metrics-equal-summed-billing-details-standard-twin-has-none"
GROUP = "metrics-and-billing"
SERVICES = ["cloudwatch", "stepfunctions"]

#: Wait seconds per execution. Distinct on purpose: the billed durations then differ, so a target
#: that publishes count x constant (or the last value) cannot land on the right Sum by accident.
_WAITS = (0, 1, 2)
#: ExpressExecutionBilledMemory is published in Bytes at 10^6 (not 2^20) bytes per billed MB.
_BYTES_PER_BILLED_MB = 1_000_000
_EXPRESS_METRICS = ("ExpressExecutionMemory", "ExpressExecutionBilledDuration",
                    "ExpressExecutionBilledMemory")
_METRIC_BUDGET_S = 420.0
#: The least a reading must hold unchanged; a reading that took longer to first appear holds
#: for that long instead, so it still spans a publication interval.
_STABLE_WINDOW_S = 10


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:metrics",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """AWS/States Express billed duration and memory Sums equal the summed sync billingDetails.

    ExpressExecutionMemory has one sample per execution; a STANDARD twin has no Express series.
    """
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _states_role(ctx)
    log_group_arn = _log_group(ctx)
    express = _state_machine(ctx, sfn, role_arn, "x-", "EXPRESS", log_group_arn)
    standard = _state_machine(ctx, sfn, role_arn, "std-", "STANDARD", None)

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

    billed_ms: list[int] = []
    billed_mb: list[int] = []
    for wait in _WAITS:
        resp = sfn.start_sync_execution(stateMachineArn=express, input=json.dumps({"wait": wait}))
        assert resp["status"] == "SUCCEEDED", (
            f"sync execution with wait={wait} ended {resp['status']!r} "
            f"({resp.get('error')!r}/{resp.get('cause')!r}); expected 'SUCCEEDED'"
        )
        assert json.loads(resp["output"]) == {"wait": wait, "done": True}, (
            f"sync execution with wait={wait} returned output {resp.get('output')!r}; the Pass state "
            f"must merge done=true into the input"
        )
        bd = resp["billingDetails"]
        ms, mb = bd["billedDurationInMilliseconds"], bd["billedMemoryUsedInMB"]
        assert ms >= wait * 1000 and ms % 100 == 0, (
            f"billedDurationInMilliseconds {ms!r} for an execution that Waited {wait}s must be at "
            f"least {wait * 1000} and a multiple of 100 (billing rounds up to the next 100 ms)"
        )
        assert mb > 0 and mb % 64 == 0, (
            f"billedMemoryUsedInMB {mb!r} must be a positive multiple of the 64 MB billing chunk"
        )
        billed_ms.append(ms)
        billed_mb.append(mb)
    assert len(set(billed_ms)) == len(_WAITS), (
        f"billed durations {billed_ms!r} for waits {_WAITS!r} are not distinct; the Sum below is "
        f"only discriminating if they differ"
    )

    std_arns = [
        sfn.start_execution(stateMachineArn=standard, input=json.dumps({"wait": 0}))["executionArn"]
        for _ in _WAITS
    ]
    for arn in std_arns:
        status = _poll_until(
            lambda a=arn: sfn.describe_execution(executionArn=a)["status"],
            lambda s: s != "RUNNING",
            timeout_s=120.0,
            interval_s=2.0,
            description=f"standard twin execution {arn} finishing",
        )
        assert status == "SUCCEEDED", f"standard twin execution {arn} ended {status!r}"

    def stats(machine: str, metric: str):
        dps = cw.get_metric_statistics(
            Namespace="AWS/States",
            MetricName=metric,
            Dimensions=[{"Name": "StateMachineArn", "Value": machine}],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum", "SampleCount", "Maximum"],
        )["Datapoints"]
        if not dps:
            return None
        return (
            float(sum(d["Sum"] for d in dps)),
            float(sum(d["SampleCount"] for d in dps)),
            max(d["Maximum"] for d in dps),
            sorted({d.get("Unit") for d in dps}),
        )

    def reading():
        r = {m: stats(express, m) for m in _EXPRESS_METRICS}
        r["std_ok"] = stats(standard, "ExecutionsSucceeded")
        # Complete only once every series carries all N samples; a partial aggregate re-polls.
        if any(v is None for v in r.values()):
            return None
        if any(r[m][1] < len(_WAITS) for m in _EXPRESS_METRICS) or r["std_ok"][0] < len(_WAITS):
            return None
        return r

    got = _poll_until_stable(
        reading,
        window_s=_STABLE_WINDOW_S,
        timeout_s=_METRIC_BUDGET_S,
        description="AWS/States Express billing series for the express machine and "
        "ExecutionsSucceeded for the standard twin",
    )

    dur_sum, dur_n, _, dur_unit = got["ExpressExecutionBilledDuration"]
    assert dur_sum == float(sum(billed_ms)), (
        f"ExpressExecutionBilledDuration Sum is {dur_sum!r}; the three StartSyncExecution responses "
        f"billed {billed_ms!r} ms, so it must be {float(sum(billed_ms))!r}"
    )
    assert dur_n == float(len(_WAITS)) and dur_unit == ["Milliseconds"], (
        f"ExpressExecutionBilledDuration has SampleCount {dur_n!r} unit {dur_unit!r}; expected "
        f"{len(_WAITS)} samples in Milliseconds — one per execution"
    )

    mem_sum, mem_n, mem_max, mem_unit = got["ExpressExecutionBilledMemory"]
    want_bytes = float(sum(billed_mb) * _BYTES_PER_BILLED_MB)
    assert mem_sum == want_bytes, (
        f"ExpressExecutionBilledMemory Sum is {mem_sum!r}; the responses billed {billed_mb!r} MB, so "
        f"it must be {want_bytes!r} Bytes (10^6 per billed MB)"
    )
    assert mem_n == float(len(_WAITS)) and mem_unit == ["Bytes"], (
        f"ExpressExecutionBilledMemory has SampleCount {mem_n!r} unit {mem_unit!r}; expected "
        f"{len(_WAITS)} samples in Bytes"
    )

    used_sum, used_n, used_max, used_unit = got["ExpressExecutionMemory"]
    assert used_n == float(len(_WAITS)) and used_unit == ["Bytes"] and used_sum > 0, (
        f"ExpressExecutionMemory reads Sum {used_sum!r} SampleCount {used_n!r} unit {used_unit!r}; "
        f"expected one positive Bytes sample per execution ({len(_WAITS)})"
    )
    assert used_max <= mem_max, (
        f"ExpressExecutionMemory Maximum {used_max!r} exceeds the largest billed memory "
        f"{mem_max!r} Bytes; memory consumed is billed rounded UP to the 64 MB chunk"
    )

    std_ok_sum = got["std_ok"][0]
    assert std_ok_sum == float(len(_WAITS)), (
        f"the STANDARD twin's ExecutionsSucceeded Sum is {std_ok_sum!r}, expected {len(_WAITS)}"
    )

    # Read after the twin's own ExecutionsSucceeded is live, so absence is not "not published yet".
    for metric in _EXPRESS_METRICS:
        twin = stats(standard, metric)
        assert twin is None, (
            f"the STANDARD twin {standard} has AWS/States {metric} datapoints {twin!r}; only "
            f"EXPRESS executions are billed per duration/memory"
        )
    twin_names = set()
    for page in cw.get_paginator("list_metrics").paginate(
        Namespace="AWS/States", Dimensions=[{"Name": "StateMachineArn", "Value": standard}]
    ):
        twin_names |= {m["MetricName"] for m in page["Metrics"]}
    express_named = sorted(n for n in twin_names if n.startswith("ExpressExecution"))
    assert express_named == [], (
        f"ListMetrics for the STANDARD twin's StateMachineArn names {express_named!r}; a Standard "
        f"state machine must have no ExpressExecution* series (all names: {sorted(twin_names)!r})"
    )


_DEFINITION = json.dumps(
    {
        "Comment": "Waits $.wait seconds, then merges done=true. Deterministic, no foreign artifact.",
        "StartAt": "Hold",
        "States": {
            "Hold": {"Type": "Wait", "SecondsPath": "$.wait", "Next": "Done"},
            "Done": {"Type": "Pass", "Result": True, "ResultPath": "$.done", "End": True},
        },
    }
)
_LOG_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    "logs:CreateLogStream", "logs:PutLogEvents",
]


def _states_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-obssfn3-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "states.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description="sim2real cloudwatch__sfn express billing metrics",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__sfn"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="logs-delivery",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": _LOG_ACTIONS, "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="logs-delivery"))
    return arn


def _log_group(ctx) -> str:
    """A vended-logs group for the EXPRESS machine's level-ALL logging (content not graded)."""
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-obssfn3-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": "cloudwatch__sfn"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _state_machine(ctx, sfn, role_arn: str, label: str, kind: str, log_group_arn) -> str:
    name = ctx.unique_name(f"sim2real-obssfn3-{label}")[:80]
    kwargs = dict(
        name=name,
        definition=_DEFINITION,
        roleArn=role_arn,
        type=kind,
        tags=[{"key": "sim2real", "value": "cloudwatch__sfn"}],
    )
    if log_group_arn:
        kwargs["loggingConfiguration"] = {
            "level": "ALL",
            "includeExecutionData": True,
            "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": log_group_arn}}],
        }
    arn = _retry_on_role_propagation(
        lambda: sfn.create_state_machine(**kwargs)["stateMachineArn"],
        description=f"CreateStateMachine {name} ({kind}) accepting the fresh role {role_arn}",
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _retry_on_role_propagation(call, *, description: str):
    """Retry only the IAM-propagation AccessDeniedException (about 10 s after CreateRole) until a
    deadline that raises."""
    budget_s = 120.0
    deadline = time.monotonic() + budget_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return call()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
    raise AssertionError(f"{description} never succeeded within {budget_s}s; last refusal {last!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _poll_until_stable(probe, *, window_s, timeout_s, interval_s=15.0, description="reading"):
    """Return a non-None reading once it has held unchanged for window_s, so a late datapoint
    cannot land after the assertion."""
    deadline = time.monotonic() + timeout_s
    started, first_t = time.monotonic(), None
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if last is None:
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
            first_t = now if first_t is None else first_t
        elif now - anchor_t >= max(window_s, first_t - started):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} never held one complete value for {window_s}s within {timeout_s}s; "
        f"last reading was {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
