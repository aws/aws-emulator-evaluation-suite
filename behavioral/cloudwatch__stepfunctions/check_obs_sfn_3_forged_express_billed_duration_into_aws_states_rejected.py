"""obs-sfn-3-forged-express-billed-duration-into-aws-states-rejected."""

# PutMetricData(Namespace="AWS/States", MetricName="ExpressExecutionBilledDuration",
# Dimensions=[StateMachineArn=<a live EXPRESS machine>]) is refused with HTTP 400, Error.Code
# "InvalidParameterValue", Message "The value AWS/ for parameter Namespace is invalid.". The genuine
# series for that machine reads exactly the one StartSyncExecution's billedDurationInMilliseconds.

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-sfn-3-forged-express-billed-duration-into-aws-states-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "stepfunctions"]

_NS = "AWS/States"
#: AWS names only the reserved prefix, not the namespace the caller sent.
_NS_REFUSAL = "The value AWS/ for parameter Namespace is invalid."
_METRIC = "ExpressExecutionBilledDuration"
#: A value no single Pass execution can be billed, so its appearance anywhere is unambiguous.
_SPOOF = 987654300.0
_METRIC_BUDGET_S = 420.0
_STABLE_WINDOW_S = 60.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
@tags(
    "axis:rejection",
    "cap:c2",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """PutMetricData forging AWS/States ExpressExecutionBilledDuration for a live EXPRESS machine is
    refused with 400 InvalidParameterValue and the genuine series reads only the billed duration, while
    the same datum in a custom namespace reads back: nobody may rewrite the billing series."""
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _states_role(ctx)
    express = _express_machine(ctx, sfn, role_arn)
    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

    resp = sfn.start_sync_execution(stateMachineArn=express, input=json.dumps({"ok": True}))
    assert resp["status"] == "SUCCEEDED", (
        f"the express machine's sync execution ended {resp['status']!r} "
        f"({resp.get('error')!r}/{resp.get('cause')!r}); expected 'SUCCEEDED'"
    )
    billed = float(resp["billingDetails"]["billedDurationInMilliseconds"])
    assert 0 < billed < _SPOOF, f"billedDurationInMilliseconds {billed!r} is not a plausible bill"

    datum = {
        "MetricName": _METRIC,
        "Dimensions": [{"Name": "StateMachineArn", "Value": express}],
        "Value": _SPOOF,
        "Unit": "Milliseconds",
    }

    # ---- the refusal ---------------------------------------------------------------------------- #
    code, status, message = _error(lambda: cw.put_metric_data(Namespace=_NS, MetricData=[datum]))
    assert (code, status, message) == ("InvalidParameterValue", 400, _NS_REFUSAL), (
        f"PutMetricData into the service-owned namespace {_NS!r} returned code={code!r} "
        f"status={status!r} message={message!r}; real AWS refuses it with "
        f"InvalidParameterValue/400 {_NS_REFUSAL!r}"
    )

    # ---- positive control: the same datum is writable outside AWS/ ----------------------------- #
    custom_ns = ctx.unique_name("Sim2Real/obssfn3-")
    cw.put_metric_data(Namespace=custom_ns, MetricData=[datum])
    custom = _poll_until(
        lambda: _series(cw, custom_ns, express, window_start),
        lambda r: r is not None,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=10.0,
        description=f"the control datum in custom namespace {custom_ns!r} reading back",
    )
    assert custom == (_SPOOF, 1.0, _SPOOF), (
        f"the same datum put into {custom_ns!r} read back as (Sum, SampleCount, Max)={custom!r}, "
        f"expected ({_SPOOF}, 1.0, {_SPOOF})"
    )

    # ---- effect absent: the genuine series carries exactly the real bill ----------------------- #
    real = _poll_until_stable(
        lambda: _series(cw, _NS, express, window_start),
        window_s=_STABLE_WINDOW_S,
        timeout_s=_METRIC_BUDGET_S,
        description=f"AWS/States {_METRIC} for the express machine",
    )
    assert real[2] != _SPOOF, (
        f"the refused value {_SPOOF} reached the service-owned series AWS/States {_METRIC} "
        f"StateMachineArn={express}: (Sum, SampleCount, Max)={real!r}"
    )
    assert real == (billed, 1.0, billed), (
        f"AWS/States {_METRIC} for the express machine reads (Sum, SampleCount, Max)={real!r}; its "
        f"one sync execution was billed {billed} ms, so it must be ({billed}, 1.0, {billed})"
    )


# ===== helpers =====
_DEFINITION = json.dumps(
    {"StartAt": "Fine", "States": {"Fine": {"Type": "Pass", "End": True}}}
)


def _error(fn) -> tuple[str, int, str]:
    """(Error.Code, HTTP status, Error.Message) of the call. An unexpected SUCCESS raises: the forged datum was
    accepted, which is the strongest failure this check exists to catch."""
    try:
        fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response["ResponseMetadata"]["HTTPStatusCode"],
            exc.response["Error"].get("Message"),
        )
    raise AssertionError(
        f"PutMetricData into {_NS!r} SUCCEEDED; a customer write into the service-owned AWS/ "
        f"namespace must be refused"
    )


def _series(cw, namespace: str, machine: str, start: datetime):
    dps = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=_METRIC,
        Dimensions=[{"Name": "StateMachineArn", "Value": machine}],
        StartTime=start,
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
    )


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
        Description="sim2real cloudwatch__sfn forged billing metric",
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__sfn"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _express_machine(ctx, sfn, role_arn: str) -> str:
    name = ctx.unique_name("sim2real-obssfn3-forge-")[:80]
    budget_s = 120.0
    deadline = time.monotonic() + budget_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_DEFINITION,
                roleArn=role_arn,
                type="EXPRESS",
                tags=[{"key": "sim2real", "value": "cloudwatch__sfn"}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            # Only the IAM-propagation refusal for the fresh role is retried.
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
    raise AssertionError(
        f"CreateStateMachine {name} never accepted the fresh role within {budget_s}s; last {last!r}"
    )


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
    deadline = time.monotonic() + timeout_s
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if last is None:
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
        elif now - anchor_t >= window_s:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} never held one complete value for {window_s}s within {timeout_s}s; "
        f"last reading was {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
