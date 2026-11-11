"""recursive-invocations-dropped-is-emitted-only-when-the-guardrail-terminates."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "recursive-invocations-dropped-is-emitted-only-when-the-guardrail-terminates"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

#: Well past the ~16-invocation guardrail for the Terminate arm; the Allow arm stops itself here
#: because Allow really permits the recursion.
_MAX_DEPTH = 24

_METRIC_BUDGET_S = 600.0
_CHAIN_BUDGET_S = 300.0
#: The twin's absence hold, a fixed window read after the positive metric has landed.
_ABSENCE_HOLD_S = 10.0
_ROLE_PROPAGATION_BUDGET_S = 180.0
#: Quiet time after the Allow chain reaches its ceiling; a later Terminate hop only raises a depth
#: that is already below the ceiling, so a short window loses nothing.
_SETTLE_S = 5.0

#: The handler invokes itself with depth+1 until _MAX_DEPTH, reporting each hop to a side-channel
#: queue so the chain's real depth is observed rather than inferred. It runs inside Lambda, where
#: boto3 is the runtime-provided SDK.
_HANDLER = '''
import json
import os
import boto3

MAX_DEPTH = {max_depth}


def handler(event, context):
    depth = int(event.get("depth", 0))
    sqs = boto3.client("sqs")
    sqs.send_message(
        QueueUrl=os.environ["SIDE_CHANNEL"],
        MessageBody=json.dumps({{"depth": depth, "fn": context.function_name}}),
    )
    if depth >= MAX_DEPTH:
        return {{"stopped_at": depth}}
    boto3.client("lambda").invoke(
        FunctionName=context.function_name,
        InvocationType="Event",
        Payload=json.dumps({{"depth": depth + 1}}).encode("utf-8"),
    )
    return {{"forwarded": depth + 1}}
'''


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/invocation-recursion.html
@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """When RecursiveLoop=Terminate cuts a self-invoking chain short, AWS/Lambda publishes
    RecursiveInvocationsDropped (Count, per FunctionName); an Allow twin running the same chain
    to completion publishes none.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/invocation-recursion.html"""
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    side_channel_url, side_channel_arn = _queue(ctx)
    role_arn = _lambda_role(ctx, side_channel_arn)

    terminating = _function(ctx, lam, role_arn, side_channel_url, "term-")
    allowing = _function(ctx, lam, role_arn, side_channel_url, "allow-")

    # Explicitly set BOTH, so neither arm depends on the account default.
    for name, mode in ((terminating, "Terminate"), (allowing, "Allow")):
        resp = lam.put_function_recursion_config(FunctionName=name, RecursiveLoop=mode)
        assert resp["RecursiveLoop"] == mode, (
            f"PutFunctionRecursionConfig on {name} echoed {resp['RecursiveLoop']!r}, expected "
            f"{mode!r}; the two arms must differ in exactly this setting"
        )
        got = lam.get_function_recursion_config(FunctionName=name)["RecursiveLoop"]
        assert got == mode, (
            f"GetFunctionRecursionConfig on {name} reports {got!r}, expected {mode!r} — the setting "
            f"must have persisted before the chains are driven"
        )

    # ---- drive both chains ---------------------------------------------------------------------- #
    for name in (terminating, allowing):
        resp = lam.invoke(
            FunctionName=name,
            InvocationType="Event",
            Payload=json.dumps({"depth": 0}).encode("utf-8"),
        )
        assert resp["StatusCode"] == 202, (
            f"the seed async invoke of {name} returned StatusCode {resp['StatusCode']!r}, expected "
            f"202; neither chain has started so nothing below is attributable"
        )

    # The chains report every hop to the side channel, so their real depths are read at the CONSUMER.
    depths = _collect_depths(
        ctx,
        side_channel_url,
        expected_functions={terminating, allowing},
        timeout_s=_budget_s(ctx, _CHAIN_BUDGET_S),
        description="both self-invoking chains reporting their hops to the side-channel queue",
    )
    term_depth = max(depths.get(terminating, {-1}))
    allow_depth = max(depths.get(allowing, {-1}))
    assert allow_depth == _MAX_DEPTH, (
        f"the RecursiveLoop=Allow chain on {allowing} reached depth {allow_depth}, expected it to run "
        f"to its own self-imposed ceiling of {_MAX_DEPTH}. If Allow does not permit the recursion, "
        f"the twin is not a control and the absence asserted below means nothing"
    )
    assert term_depth < allow_depth, (
        f"the RecursiveLoop=Terminate chain on {terminating} reached depth {term_depth} and the "
        f"Allow twin reached {allow_depth}; the guardrail must actually cut the chain SHORT, and "
        f"equal depths mean nothing was terminated for the metric to report"
    )

    # ---- terminal read at CloudWatch ---------------------------------------------------------- #
    window_start = datetime.now(timezone.utc) - timedelta(minutes=25)

    def _dps(fn: str) -> list[dict]:
        return cw.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName="RecursiveInvocationsDropped",
            Dimensions=[{"Name": "FunctionName", "Value": fn}],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum", "SampleCount"],
        )["Datapoints"]

    def _sum(fn: str) -> float | None:
        dps = _dps(fn)
        return float(sum(d["Sum"] for d in dps)) if dps else None

    dropped = _poll_until(
        lambda: _sum(terminating),
        lambda v: v is not None and v >= 1.0,
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S),
        interval_s=2.0, ctx=ctx,
        description=(
            f"AWS/Lambda RecursiveInvocationsDropped reaching >= 1 for FunctionName={terminating}, "
            f"whose chain the Terminate guardrail cut at depth {term_depth} while the Allow twin ran "
            f"to {allow_depth}"
        ),
    )
    # The drop count is undocumented, so only a non-zero Sum is required; the twin discriminates.
    assert dropped >= 1.0, (
        f"AWS/Lambda RecursiveInvocationsDropped Sum for FunctionName={terminating} read "
        f"{dropped!r}, expected at least 1.0. Lambda cut this chain at depth {term_depth} against "
        f"the twin's {allow_depth}, so at least one invocation was dropped and must be reported. No "
        f"exact count is demanded: how many Lambda drops once it breaks a loop is undocumented"
    )

    dps = _dps(terminating)
    assert dps, f"RecursiveInvocationsDropped vanished on re-read for {terminating}: {dps!r}"
    units = {d.get("Unit") for d in dps}
    assert units == {"Count"}, (
        f"AWS/Lambda RecursiveInvocationsDropped datapoints for FunctionName={terminating} carry "
        f"Unit(s) {units!r}, expected exactly {{'Count'}}"
    )

    sets = _dimension_sets(cw, "AWS/Lambda", "FunctionName", terminating)
    assert ("FunctionName",) in sets, (
        f"ListMetrics reports dimension sets {sorted(sets)!r} for the AWS/Lambda series naming "
        f"FunctionName={terminating}; the per-function ('FunctionName',) series must exist, because "
        f"an account-level drop counter cannot tell an operator WHICH function is looping"
    )

    # ---- the twin: RecursiveLoop=Allow drops nothing, held after the positive ------------------- #
    _assert_stays(
        lambda: _sum(allowing),
        None,
        hold_s=_ABSENCE_HOLD_S,
        interval_s=2.0,
        description=(
            f"the RecursiveLoop=Allow twin {allowing}, which ran the SAME self-invoking chain to "
            f"depth {allow_depth} on the same code and the same role, publishes no "
            f"RecursiveInvocationsDropped datapoint"
        ),
    )

    # ---- positive control, after the negative ------------------------------------------------- #
    final = _sum(terminating)
    assert final is not None and final >= 1.0, (
        f"after the twin's absence window RecursiveInvocationsDropped for {terminating} read "
        f"{final!r}, expected it still >= 1.0 — the twin's absence is only meaningful while the "
        f"positive series is served"
    )


def _queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cwlam-side-"),
        tags={"sim2real": "cloudwatch__lambda"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _lambda_role(ctx, side_channel_arn: str) -> str:
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-cwlam-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
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
        ),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )["Role"]["Arn"]
    policy_name = "sim2real-cwlam"
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sqs:SendMessage"],
                        "Resource": side_channel_arn,
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["lambda:InvokeFunction"],
                        # Region and account come from the caller, never a literal.
                        "Resource": f"arn:aws:lambda:{ctx.region}:{account}:function:sim2real-cwlam-*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": f"arn:aws:logs:{ctx.region}:{account}:*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return arn


def _function(ctx, lam, role_arn: str, side_channel_url: str, label: str) -> str:
    name = ctx.unique_name(f"sim2real-cwlam-{label}")[:64]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", _HANDLER.format(max_depth=_MAX_DEPTH))
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    _retry_on_role_propagation(
        lambda: lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="handler.handler",
            Code={"ZipFile": buf.getvalue()},
            Timeout=30,
            MemorySize=128,
            Environment={"Variables": {"SIDE_CHANNEL": side_channel_url}},
            Tags={"sim2real": "cloudwatch__lambda"},
        ),
        description=f"CreateFunction {name} accepting the freshly created role {role_arn}",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    return name


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _retry_on_role_propagation(call, *, description: str):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidParameterValueException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        f"{description} never succeeded within {_ROLE_PROPAGATION_BUDGET_S}s; last refusal {last!r}"
    )


def _collect_depths(
    ctx, queue_url: str, *, expected_functions: set[str], timeout_s: float, description: str
) -> dict[str, set[int]]:
    """Drain both chains' hops until the ceiling is seen and _SETTLE_S passes with no new one."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen: dict[str, set[int]] = {}
    settled_at: float | None = None
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        new_max = False
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            bucket = seen.setdefault(body["fn"], set())
            if body["depth"] not in bucket:
                bucket.add(body["depth"])
                new_max = True
        if new_max:
            settled_at = None
        ready = expected_functions <= set(seen) and any(
            max(v) >= _MAX_DEPTH for v in seen.values()
        )
        if ready:
            if settled_at is None:
                settled_at = time.monotonic()
            elif time.monotonic() - settled_at >= _SETTLE_S:
                return seen
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    if expected_functions <= set(seen):
        return seen
    raise AssertionError(
        f"{description} did not happen within {timeout_s}s; hops seen were "
        f"{ {k: sorted(v) for k, v in seen.items()} !r}, expected reports from all of "
        f"{sorted(expected_functions)!r}"
    )


def _dimension_sets(cw, namespace: str, dim_name: str, dim_value: str) -> set[tuple[str, ...]]:
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": dim_name, "Value": dim_value}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


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


def _assert_stays(probe, expected, *, hold_s, interval_s=2.0, description="reading"):
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description}: read {got!r}, expected it to stay {expected!r} for the whole {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
